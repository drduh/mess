package processing

import (
	"testing"
	"time"

	"github.com/drduh/mess/internal/event"
)

func when(t string) time.Time {
	when, err := time.Parse(time.RFC3339, t)
	if err != nil {
		panic(err)
	}

	return when
}

func TestTimecardSplitsOnTheTerminal(t *testing.T) {
	events := []event.Event{
		{Time: when("2026-11-09T09:00:00Z"), TTY: "/dev/ttys001", Cmd: []string{"ls"}},
		{Time: when("2026-11-09T09:30:00Z"), TTY: "/dev/ttys001", Cmd: []string{"git"}},
		{Time: when("2026-11-09T09:45:00Z"), Cmd: []string{"trustd"}},
		{Time: when("2026-11-15T03:00:00Z"), Cmd: []string{"mdworker"}},
	}
	tc := BuildTimecard(events, 0, nil)

	if tc.Person[0][9] != 2 {
		t.Errorf("Monday 09:00 attended = %d, want 2", tc.Person[0][9])
	}

	if tc.System[0][9] != 1 {
		t.Errorf("Monday 09:00 alone = %d, want 1", tc.System[0][9])
	}

	if tc.System[6][3] != 1 {
		t.Errorf("Sunday 03:00 alone = %d, want 1; rows run Monday first", tc.System[6][3])
	}

	if tc.Totals["person"] != 2 || tc.Totals["system"] != 2 {
		t.Errorf("totals = %v", tc.Totals)
	}
}

func TestTimecardUsesTheReadersClock(t *testing.T) {
	events := []event.Event{{Time: when("2026-11-09T01:00:00Z"), Cmd: []string{"x"}}}
	utc := BuildTimecard(events, 0, nil)
	if utc.System[0][1] != 1 {
		t.Fatalf("in UTC it should be Monday 01:00")
	}

	west := BuildTimecard(events, -7*60, nil)
	if west.System[6][18] != 1 {
		t.Errorf("seven hours west should be Sunday 18:00, got %v", west.System[6])
	}
	if west.Offset != -420 {
		t.Errorf("offset = %d", west.Offset)
	}
}
