package processing

import (
	"testing"

	"github.com/drduh/mess/internal/event"
)

// Interner must be invisible.
func TestLabellerAnswersAsTheFunctionDoes(t *testing.T) {
	triples := []struct {
		sign, team string
		sys        bool
	}{
		{"com.apple.bird", "", true},
		{"com.apple.bird", "", false},
		{"org.mozilla.firefox", "43AQ936H96", false},
		{"org.mozilla.firefox", "", false},
		{"", "", false},
		{"", "TEAM", false},
		{"a.out", "", false},
	}

	l := newLabeller()

	for round := 0; round < 3; round++ {
		for _, c := range triples {
			got, want := l.label(
				c.sign, c.team, c.sys), signerLabel(c.sign, c.team, c.sys)
			if got != want {
				t.Errorf("round %d, %+v: got %q, want %q", round, c, got, want)
			}
		}
	}

	seen := map[string]int{}
	for _, c := range triples {
		seen[l.label(c.sign, c.team, c.sys)]++
	}

	if len(seen) != len(triples) {
		t.Errorf("%d triples produced %d labels; they are meant to be distinct: %v",
			len(triples), len(seen), seen)
	}
}

// Caller and image read different fields.
func TestLabellerReadsTheRightSide(t *testing.T) {
	e := event.Event{
		Sign: "com.apple.xpc.proxy", Team: "", Sys: true,
		Target: event.Target{
			Path: "/usr/bin/git",
			Sign: "org.git",
			Team: "TEAM",
			Sys: false,
		},
	}

	l := newLabeller()
	if got, want := l.caller(&e), signerLabel(
			e.Sign, e.Team, e.Sys); got != want {
		t.Errorf("caller = %q, want %q", got, want)
	}

	if got, want := l.image(&e), signerLabel(
			e.Target.Sign, e.Target.Team, e.Target.Sys); got != want {
		t.Errorf("image = %q, want %q", got, want)
	}

	if l.caller(&e) == l.image(&e) {
		t.Error("the two sides of this event share a label")
	}
}

func TestLabellerLineage(t *testing.T) {
	l := newLabeller()
	for round := 0; round < 3; round++ {
		for _, c := range [][2]string{
			{"", ""},
			{"/bin/zsh", "/usr/bin/ls"},
			{"/bin/zsh", "/usr/bin/git"},
			{"/usr/bin/git", "/bin/zsh"},
		} {
			if got, want := l.lineage(c[0], c[1]), c[0]+" -> "+c[1]; got != want {
				t.Errorf("round %d: lineage%v = %q, want %q", round, c, got, want)
			}
		}
	}

	if a, b := l.lineage("x", "y"), l.lineage("y", "x"); a == b {
		t.Error("a lineage reads the same in both directions")
	}
}
