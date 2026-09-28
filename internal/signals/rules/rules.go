// Package rules contains the signals.

package rules

import (
	"sort"
	"strings"

	"github.com/drduh/mess/internal/signals"
)

var All = mustAssemble(order, placeRules)

// order is the reading order: alert, then notice, then context.
var order = []string{

	// Alerts
	"ran_from_loose",
	"script_from_loose",

	// Notices
	"hidden_path",
	"cwd_other_home",
	"writable",
	"relative_argv0",
}

type split struct {
	key     func(e *signals.Seen) string
	by      func(e *signals.Seen) bool
	yes, no signals.Rule
}

// mustAssemble lays the families out in reading order.
func mustAssemble(order []string, families ...[]signals.Rule) []signals.Rule {
	byID := map[string]signals.Rule{}

	for _, family := range families {
		for _, r := range family {
			if _, twice := byID[r.ID]; twice {
				panic("rules: " + r.ID + " is defined in two places")
			}

			byID[r.ID] = r
		}
	}

	out := make([]signals.Rule, 0, len(order))
	placed := map[string]bool{}

	for _, id := range order {
		r, ok := byID[id]
		switch {
		case !ok:
			panic("rules: the order names " + id + ", which no family defines")
		case placed[id]:
			panic("rules: the order names " + id + " twice")
		}

		placed[id] = true
		out = append(out, r)
	}

	var left []string
	for id := range byID {
		if !placed[id] {
			left = append(left, id)
		}
	}

	if len(left) > 0 {
		sort.Strings(left)
		panic("rules: not in reading order: " + strings.Join(left, ", "))
	}

	return out
}

func (s split) rules() []signals.Rule {
	for _, h := range []signals.Rule{s.yes, s.no} {
		if h.Match != nil || h.Walk != nil {
			panic("rules: " + h.ID + " is half of a split and brings its own matcher")
		}
	}

	yes, no := s.yes, s.no
	yes.Match = func(e *signals.Seen) string {
		if !s.by(e) {
			return ""
		}

		return s.key(e)
	}

	no.Match = func(e *signals.Seen) string {
		if s.by(e) {
			return ""
		}

		return s.key(e)
	}

	return []signals.Rule{yes, no}
}
