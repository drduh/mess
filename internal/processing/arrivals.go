package processing

import (
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/tally"
)

// Arrival is seen inside the window and never before it.
type Arrival struct {
	Key   string    `json:"key"`
	Count int       `json:"count"`
	First time.Time `json:"first"`
	Note  string    `json:"note"`
}

// Arrivals is the difference between two windows of the capture.
type Arrivals struct {
	Commands []Arrival `json:"commands"`
	Binaries []Arrival `json:"binaries"`
	Teams    []Arrival `json:"teams"`
	Signs    []Arrival `json:"signs"`

	Baseline int       `json:"baseline"`
	Window   int       `json:"window"`
	From     time.Time `json:"from"`
}

// seen collects the keys one capture contains.
type seen struct {
	commands, binaries, teams, signs map[string]bool
}

func survey(events []event.Event, cache *classify.Cache) seen {
	s := seen{map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}}
	for i := range events {
		e := &events[i]
		s.commands[cache.Template(e.Cmd)] = true
		s.binaries[classify.Command(e.Path)] = true
		s.binaries[classify.Command(e.Image())] = true

		if e.Team != "" {
			s.teams[e.Team] = true
		}

		if e.Sign != "" {
			s.signs[e.Sign] = true
		}
	}

	return s
}

// NewIn reports the window to baseline diff.
func NewIn(baseline, window []event.Event, from time.Time, top int, cache *classify.Cache) Arrivals {
	old := survey(baseline, cache)
	out := Arrivals{
		Baseline: len(baseline),
		Window:   len(window),
		From:     from,
		Commands: []Arrival{},
		Binaries: []Arrival{},
		Teams:    []Arrival{},
		Signs:    []Arrival{},
	}

	type seen struct {
		count int
		first time.Time
		note  string
	}

	add := func(m map[string]*seen, key, note string, at time.Time) {
		if key == "" {
			return
		}

		t := m[key]
		if t == nil {
			m[key] = &seen{1, at, note}
			return
		}

		t.count++
		if at.Before(t.first) {
			t.first = at
		}
	}

	cmds := map[string]*seen{}
	bins := map[string]*seen{}
	teams := map[string]*seen{}
	signs := map[string]*seen{}

	for i := range window {
		e := &window[i]
		if shape := cache.Template(e.Cmd); shape != "" && !old.commands[shape] {
			add(cmds, shape, signerOf(*e), e.Time)
		}

		if caller := classify.Command(e.Path); !old.binaries[caller] {
			add(bins, caller, classify.Kind(caller, e.Path), e.Time)
		}

		img := e.Image()
		if name := classify.Command(img); !old.binaries[name] {
			add(bins, name, classify.Kind(name, img), e.Time)
		}

		if e.Team != "" && !old.teams[e.Team] {
			add(teams, e.Team, "", e.Time)
		}

		if e.Sign != "" && !old.signs[e.Sign] {
			add(signs, e.Sign, signerOf(*e), e.Time)
		}
	}

	rank := func(m map[string]*seen) []Arrival {
		out := make([]Arrival, 0, len(m))
		counts := make([]Count, 0, len(m))

		for k, t := range m {
			counts = append(counts, Count{Key: k, N: t.count})
		}

		for _, c := range tally.SortTop(counts, top) {
			t := m[c.Key]
			out = append(out, Arrival{c.Key, t.count, t.first, t.note})
		}

		return out
	}

	out.Commands = rank(cmds)
	out.Binaries = rank(bins)
	out.Teams = rank(teams)
	out.Signs = rank(signs)

	return out
}

// signerOf names who vouched for the caller.
func signerOf(e event.Event) string {
	switch {
	case e.Sys:
		return "Apple"
	case e.Team == "":
		return "unsigned"
	default:
		return e.Team
	}
}
