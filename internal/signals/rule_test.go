package signals

import (
	"strings"
	"testing"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
)

// Validate refuses malformed rules.
func TestValidateRefusesEachFault(t *testing.T) {
	good := Rule{ID: "ok_rule", Title: "t", Tier: Notice, Scope: "path",
		Summary: "s", Because: "b", Match: func(*Seen) string { return "" }}
	if err := good.Validate(); err != nil {
		t.Fatalf("a good rule failed: %v", err)
	}

	cases := []struct {
		name string
		mod  func(*Rule)
		want string
	}{
		{"no id", func(r *Rule) { r.ID = "" }, "needs an id"},
		{"bad id", func(r *Rule) { r.ID = "Bad-Id" }, "lower-case"},
		{"no title", func(r *Rule) { r.Title = "" }, "title"},
		{"no summary", func(r *Rule) { r.Summary = "" }, "summary"},
		{"no because", func(r *Rule) { r.Because = "" }, "Because"},
		{"bad tier", func(r *Rule) { r.Tier = Tier(9) }, "tier"},
		{"bad scope", func(r *Rule) { r.Scope = "vibe" }, "scope"},
		{"neither", func(r *Rule) { r.Match = nil }, "exactly one"},
		{"both", func(r *Rule) {
			r.Walk = func(pids.Capture,
				func(event.Event, string, int)) {
			}
		}, "exactly one"},
		{"threshold without measure", func(r *Rule) {
			r.Tune = &Tunable{
				Key: "k", Label: "l", Unit: "seconds", Keep: "below",
				Default: 1, Choices: []int{1}, Note: "n",
			}
		}, "nothing measured"},
		{"measure without threshold", func(r *Rule) {
			r.Measure = func(event.Event) int { return 0 }
		}, "nothing thresholds"},
		{"negative cap", func(r *Rule) { r.Cap = -1 }, "cap"},
		{"search on a file row", func(r *Rule) {
			r.Scope = "file"
			r.Find = func(string) string { return "x" }
		}, "has no search"},
	}

	for _, c := range cases {
		r := good
		c.mod(&r)
		err := r.Validate()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want it to mention %q", c.name, err, c.want)
		}
	}
}

// A threshold declares everything its control needs.
func TestTunableMustDeclareItself(t *testing.T) {
	good := func() Rule {
		return Rule{ID: "m", Title: "t", Tier: Notice, Scope: "path", Summary: "s", Because: "b",
			Match:   func(*Seen) string { return "" },
			Measure: func(event.Event) int { return 0 },
			Tune: &Tunable{Key: "new_age", Label: "Ran within", Unit: "seconds",
				Keep: "below", Default: 1800, Choices: []int{900, 1800}, Note: "n"}}
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("a well-declared threshold failed: %v", err)
	}

	for _, c := range []struct {
		name string
		mod  func(*Tunable)
		want string
	}{
		{"no key", func(x *Tunable) { x.Key = "" }, "key"},
		{"no label", func(x *Tunable) { x.Label = "" }, "label"},
		{"no note", func(x *Tunable) { x.Note = "" }, "note"},
		{"odd unit", func(x *Tunable) { x.Unit = "furlongs" }, "seconds or count"},
		{"odd direction", func(x *Tunable) { x.Keep = "sideways" }, "below or above"},
		{"no choices", func(x *Tunable) { x.Choices = nil }, "no choices"},
		{"shouty key", func(x *Tunable) { x.Key = "NewAge" }, "key"},
		{"default off the list", func(x *Tunable) { x.Default = 7 }, "not among its choices"},
	} {
		r := good()
		tune := *r.Tune
		c.mod(&tune)
		r.Tune = &tune

		err := r.Validate()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want it to mention %q", c.name, err, c.want)
		}
	}
}

// A join is declared by the rule, not inferred.
func TestJoinIsDeclaredAndClosed(t *testing.T) {
	good := Rule{ID: "j", Title: "t", Tier: Alert, Scope: "command", Summary: "s", Because: "b",
		Match: func(*Seen) string { return "" }}
	for join, want := range map[string]bool{
		"": true, "job": true, "jobs": false, "process": false,
	} {
		r := good
		r.Join = join

		if err := r.Validate(); (err == nil) != want {
			t.Errorf("join %q: Validate = %v, want ok=%v", join, err, want)
		}
	}
}
