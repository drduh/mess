package signals

import (
	"sort"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
)

type rows struct {
	rule   *Rule
	counts []int
	lost   []int
	byKey  map[string]*acc
	bucket func(time.Time) int
	sig    Signal
}

type acc struct {
	Row
	measured bool
	marks    map[string]bool
	seen     map[string]bool
}

const defaultCap = 12

var markOrder = []string{"root", "third-party", "writable", "untyped"}

func marks(e event.Event) []string {
	var out []string

	if e.UID == 0 || (e.Target.Known() && e.Target.UID == 0) {
		out = append(out, "root")
	}

	if !e.Sys || (e.Target.Known() && !e.Target.Sys) {
		out = append(out, "third-party")
	}

	if LooseIn(&e) != "" {
		out = append(out, "writable")
	}

	if e.TTY == "" && IsPerson(e.UID) {
		out = append(out, "untyped")
	}

	return out
}

func binaries(e event.Event) []string {
	a, b := classify.Command(e.Path), ImageName(&e)
	if a == b || b == "" {
		return []string{a}
	}

	return []string{a, b}
}

func newRows(r *Rule, buckets int, bucket func(time.Time) int) *rows {
	counts := make([]int, buckets)
	return &rows{
		rule: r, byKey: map[string]*acc{}, counts: counts, bucket: bucket,
		sig: Signal{ID: r.ID, Title: r.Title, Tier: r.Tier.String(), Scope: r.Scope,
			Summary: r.Summary, Because: r.Because, Tune: r.Tune, Join: r.Join,
			Counts: counts, Rows: []Row{}},
	}
}

// add records n events of one key, seen at e.
func (rs *rows) add(e event.Event, key string, n int) {
	if key == "" || n <= 0 {
		return
	}

	a := rs.byKey[key]
	if a == nil {
		a = &acc{Row: Row{Key: key, First: e.Time, Last: e.Time, Who: []string{}},
			marks: map[string]bool{}, seen: map[string]bool{}}
		rs.byKey[key] = a
	}
	a.N += n

	if m := rs.rule.Measure; m != nil {
		if got := m(e); got >= 0 && (!a.measured || got < a.Row.Measure) {
			a.Row.Measure = got
			a.measured = true
		}
	}

	if e.Time.Before(a.First) {
		a.First = e.Time
	}

	if e.Time.After(a.Last) {
		a.Last = e.Time
	}

	if rs.rule.Scope != "file" {
		for _, m := range marks(e) {
			a.marks[m] = true
		}

		for _, w := range binaries(e) {
			if !a.seen[w] {
				a.seen[w] = true
				a.Row.Who = append(a.Row.Who, w)
			}
		}
	}

	rs.sig.Count += n
	rs.counts[rs.bucket(e.Time)] += n
	if rs.sig.First.IsZero() || e.Time.Before(rs.sig.First) {
		rs.sig.First = e.Time
	}

	if e.Time.After(rs.sig.Last) {
		rs.sig.Last = e.Time
	}
}

func (rs *rows) finish() Signal {
	rs.sig.Distinct = len(rs.byKey)
	list := make([]Row, 0, len(rs.byKey))
	for _, a := range rs.byKey {
		a.Row.Marks = inOrder(a.marks, markOrder)
		a.Row.Find = findFor(rs.rule.Scope, a.Row.Key)
		list = append(list, a.Row)
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].N != list[j].N {
			return list[i].N > list[j].N
		}

		return list[i].Key < list[j].Key
	})

	limit := rs.rule.Cap
	if limit == 0 {
		limit = defaultCap
	}

	if len(list) > limit {
		list = list[:limit]
	}

	rs.sig.Rows = list
	for i, n := range rs.counts {
		if n > 0 && i < len(rs.lost) && rs.lost[i] > 0 {
			rs.sig.Blind++
			rs.sig.Lost += rs.lost[i]
		}
	}

	return rs.sig
}

func lostPerBucket(events []event.Event, bucket func(time.Time) int, buckets int) []int {
	out := make([]int, buckets)
	event.SeqWalk(events, func(prev, cur event.Event, lost int) {
		out[bucket(cur.Time)] += lost
	}, nil)
	return out
}

func bucketer(start, end time.Time, buckets int) func(time.Time) int {
	span := end.Sub(start)
	return func(t time.Time) int {
		if span <= 0 {
			return 0
		}

		i := int(float64(t.Sub(start)) / float64(span) * float64(buckets))
		if i < 0 {
			return 0
		}

		if i >= buckets {
			return buckets - 1
		}

		return i
	}
}

func inOrder(set map[string]bool, order []string) []string {
	out := []string{}
	for _, k := range order {
		if set[k] {
			out = append(out, k)
		}
	}

	return out
}

func Build(rules []Rule, c pids.Capture, start, end time.Time, buckets int) []Signal {
	if buckets < 1 {
		buckets = 1
	}

	bucket := bucketer(start, end, buckets)
	seen := make([]Seen, len(c.Events))

	for i := range c.Events {
		seen[i].Event = &c.Events[i]
		seen[i].cache = c.Cache
	}

	lost := lostPerBucket(c.Events, bucket, buckets)
	out := make([]Signal, 0, len(rules))

	for i := range rules {
		r := &rules[i]
		rs := newRows(r, buckets, bucket)
		rs.lost = lost

		switch {
		case r.Match != nil:
			for i := range seen {
				if key := r.Match(&seen[i]); key != "" {
					rs.add(*seen[i].Event, key, 1)
				}
			}
		case r.Walk != nil:
			r.Walk(c, rs.add)
		}

		out = append(out, rs.finish())
	}

	return out
}

func ByID(list []Signal, id string) *Signal {
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}

	return nil
}

func NamedIn(list []Signal, name string) []string {
	out := []string{}
	for _, s := range list {
		for _, r := range s.Rows {
			hit := false
			for _, w := range r.Who {
				if w == name {
					hit = true
					break
				}
			}

			if hit {
				out = append(out, s.Title)
				break
			}
		}
	}

	return out
}
