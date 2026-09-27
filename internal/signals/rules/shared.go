package rules

import (
	"strings"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/signals"
)

func line(e *event.Event) string {
	return strings.Join(e.Cmd, " ")
}

// untyped is an event with nobody at a terminal.
func untyped(e *signals.Seen) bool {
	return e.TTY == ""
}

// seen lifts a predicate written over a plain event into a Match.
func seen(f func(*event.Event) string) func(*signals.Seen) string {
	return func(e *signals.Seen) string {
		return f(e.Event)
	}
}
