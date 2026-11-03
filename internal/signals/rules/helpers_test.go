package rules

import (
	"testing"
	"time"

	"github.com/drduh/mess/internal/signals"
)

func at(min int) time.Time {
	return time.Date(2026, 9, 10, 9, min, 0, 0, time.UTC)
}

func minute(n int) time.Time {
	return time.Date(2026, 9, 10, 9, n, 0, 0, time.UTC)
}

func newAt(sec int) time.Time {
	return time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC).Add(
		time.Duration(sec) * time.Second)
}

func signal(sigs []signals.Signal, id string) signals.Signal {
	for _, s := range sigs {
		if s.ID == id {
			return s
		}
	}

	return signals.Signal{}
}

func ruleByID(t *testing.T, id string) signals.Rule {
	t.Helper()
	for _, r := range All {
		if r.ID == id {
			return r
		}
	}

	t.Fatalf("no rule %q", id)

	return signals.Rule{}
}
