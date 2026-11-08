package processing

import (
	"strings"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/tally"
)

// Command is one command shape and everything that ran under it.
type Command struct {
	Template string    `json:"template"`
	Count    int       `json:"count"`
	Forms    int       `json:"forms"`
	AsRoot   int       `json:"asRoot"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`

	Callers  []Count  `json:"callers"`
	UIDs     []Count  `json:"uids"`
	Examples []string `json:"examples"`

	Counts []int `json:"counts"`
	Peak   int   `json:"peak"`
}

// Commands groups the events by command shape, busiest first.
func Commands(events []event.Event, top int, cache *classify.Cache) ([]*Command, []string) {
	byShape := map[string]*Command{}
	callers := map[string]tally.Counter{}
	uids := map[string]tally.Counter{}
	forms := map[string]tally.Counter{}
	shapes := make([]string, len(events))

	for i := range events {
		e := &events[i]
		shape := cache.Template(e.Cmd)
		shapes[i] = shape
		if shape == "" {
			continue
		}

		c := byShape[shape]
		if c == nil {
			c = &Command{Template: shape, First: e.Time, Last: e.Time}
			byShape[shape] = c
			callers[shape] = tally.Counter{}
			uids[shape] = tally.Counter{}
			forms[shape] = tally.Counter{}
		}
		c.Count++

		if e.UID == 0 {
			c.AsRoot++
		}

		if e.Time.Before(c.First) {
			c.First = e.Time
		}

		if e.Time.After(c.Last) {
			c.Last = e.Time
		}

		callers[shape].Add(classify.Command(e.Path))
		uids[shape].Add(classify.UIDKey(e.UID))
		forms[shape].Add(strings.Join(e.Cmd, " "))
	}

	ranked := make([]Count, 0, len(byShape))
	for shape, c := range byShape {
		ranked = append(ranked, Count{Key: shape, N: c.Count})
	}

	out := make([]*Command, 0, len(ranked))
	for _, r := range tally.SortTop(ranked, top) {
		c := byShape[r.Key]
		c.Callers = callers[r.Key].Top(8)
		c.UIDs = uids[r.Key].Top(8)
		c.Forms = len(forms[r.Key])
		c.Examples = []string{}
		if c.Forms > 1 {
			for _, f := range forms[r.Key].Top(4) {
				c.Examples = append(c.Examples, f.Key)
			}
		}

		out = append(out, c)
	}

	return out, shapes
}

// CommandActivity fills each shape per-bucket count.
func CommandActivity(cmds []*Command, shapes []string, events []event.Event, start, end time.Time, buckets int) {
	if buckets < 1 || len(cmds) == 0 {
		return
	}

	span := end.Sub(start)
	if span <= 0 {
		span = time.Second
	}
	index := bucketer(start, span, buckets)

	rows := make(map[string]*Command, len(cmds))
	for _, c := range cmds {
		c.Counts = make([]int, buckets)
		rows[c.Template] = c
	}

	for i := range events {
		if c := rows[shapes[i]]; c != nil {
			c.Counts[index(events[i].Time)]++
		}
	}

	for _, c := range cmds {
		for _, n := range c.Counts {
			if n > c.Peak {
				c.Peak = n
			}
		}
	}
}
