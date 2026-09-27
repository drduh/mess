package processing

import (
	"strings"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/tally"
)

// Timeline is activity bucketed over the capture.
type Timeline struct {
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Buckets int       `json:"buckets"`
	Seconds float64   `json:"seconds"` // width of bucket
	Total   []int     `json:"total"`   // every event per bucket
	Peak    int       `json:"peak"`    // largest value in Total
	Who     Who       `json:"who"`     // split by who did it
	Rows    []Track   `json:"rows"`    // busiest binaries
	Top     [][]Count `json:"top"`     // busiest images
}

// Track is binary activity across the capture.
type Track struct {
	Name   string    `json:"name"`
	Role   string    `json:"role"`
	Total  int       `json:"total"`
	Counts []int     `json:"counts"`
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
	Peak   int       `json:"peak"`
}

type Who struct {
	App    []int `json:"app"`
	Person []int `json:"person"`
	System []int `json:"system"`
}

func Actor(e event.Event) string {
	if e.TTY != "" {
		return "person"
	}

	for _, kv := range e.Env {
		if strings.HasPrefix(kv, "__CFBundleIdentifier=") {
			return "app"
		}
	}

	return "system"
}

// BuildTimeline buckets events into columns and returns top tracks.
func BuildTimeline(events []event.Event, buckets, top int, keep func(string) bool) Timeline {
	if len(events) == 0 || buckets < 1 {
		return Timeline{Buckets: 0}
	}

	start, end := events[0].Time, events[0].Time
	for _, e := range events {
		if e.Time.Before(start) {
			start = e.Time
		}

		if e.Time.After(end) {
			end = e.Time
		}
	}

	span := end.Sub(start)
	if span <= 0 {
		span = time.Second
	}

	t := Timeline{
		Start:   start,
		End:     end,
		Buckets: buckets,
		Seconds: span.Seconds() / float64(buckets),
		Total:   make([]int, buckets),
		Rows:    []Track{},
		Who: Who{
			Person: make([]int, buckets),
			App:    make([]int, buckets),
			System: make([]int, buckets),
		},
		Top: make([][]Count, buckets),
	}

	index := bucketer(start, span, buckets)

	tracks := map[string]*Track{}
	inBucket := make([]tally.Counter, buckets)

	for _, e := range events {
		name := classify.Command(e.Image())
		if keep != nil && !keep(name) {
			continue
		}

		i := index(e.Time)
		t.Total[i]++

		switch Actor(e) {
		case "person":
			t.Who.Person[i]++
		case "app":
			t.Who.App[i]++
		default:
			t.Who.System[i]++
		}

		if inBucket[i] == nil {
			inBucket[i] = tally.Counter{}
		}

		inBucket[i].Add(name)

		tr := tracks[name]
		if tr == nil {
			tr = &Track{
				Name:   name,
				Role:   classify.Role(name),
				Counts: make([]int, buckets),
				First:  e.Time,
				Last:   e.Time,
			}
			tracks[name] = tr
		}

		tr.Total++
		tr.Counts[i]++

		if e.Time.Before(tr.First) {
			tr.First = e.Time
		}

		if e.Time.After(tr.Last) {
			tr.Last = e.Time
		}
	}

	for i, v := range t.Total {
		if v > t.Peak {
			t.Peak = v
		}

		if inBucket[i] != nil {
			t.Top[i] = inBucket[i].Top(3)
		} else {
			t.Top[i] = []Count{}
		}
	}

	// Keep busiest tracks, order by volume
	ranked := make([]Count, 0, len(tracks))
	for name, tr := range tracks {
		ranked = append(ranked, Count{Key: name, N: tr.Total})
	}

	for _, c := range tally.SortTop(ranked, top) {
		tr := tracks[c.Key]

		for _, v := range tr.Counts {
			if v > tr.Peak {
				tr.Peak = v
			}
		}

		t.Rows = append(t.Rows, *tr)
	}

	return t
}

// Bucketer returns a function mapping a time onto a bucket index.
func Bucketer(start time.Time, span time.Duration, buckets int) func(time.Time) int {
	return bucketer(start, span, buckets)
}

func bucketer(start time.Time, span time.Duration, buckets int) func(time.Time) int {
	return func(at time.Time) int {
		i := int(float64(at.Sub(start)) / float64(span) * float64(buckets))

		if i >= buckets {
			i = buckets - 1
		}

		if i < 0 {
			i = 0
		}

		return i
	}
}

// TrackOf buckets events matching keep.
func TrackOf(events []event.Event, name string, start, end time.Time, buckets int, keep func(event.Event) bool) Track {
	tr := Track{Name: name, Role: classify.Role(name), Counts: make([]int, buckets)}

	if buckets < 1 {
		return tr
	}

	span := end.Sub(start)
	if span <= 0 {
		span = time.Second
	}

	index := bucketer(start, span, buckets)

	for _, e := range events {
		if !keep(e) {
			continue
		}

		if tr.Total == 0 {
			tr.First, tr.Last = e.Time, e.Time
		}

		tr.Total++
		tr.Counts[index(e.Time)]++

		if e.Time.Before(tr.First) {
			tr.First = e.Time
		}

		if e.Time.After(tr.Last) {
			tr.Last = e.Time
		}
	}

	for _, v := range tr.Counts {
		if v > tr.Peak {
			tr.Peak = v
		}
	}

	return tr
}
