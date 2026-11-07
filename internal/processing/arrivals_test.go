package processing

import (
	"testing"
	"time"

	"github.com/drduh/mess/internal/event"
)

func at(min int, path, team string, sys bool, cmd ...string) event.Event {
	return event.Event{
		Time: time.Date(2026, 9, 8, 12, min, 0, 0, time.UTC),
		Sys:  sys, Team: team, Sign: "sig." + team, Path: path, Cmd: cmd,
	}
}

func keys(a []Arrival) []string {
	out := make([]string, len(a))
	for i, x := range a {
		out[i] = x.Key
	}

	return out
}

func TestNewIn(t *testing.T) {
	baseline := []event.Event{
		at(0, "/bin/zsh", "", true, "/usr/bin/git", "status"),
		at(1, "/bin/zsh", "", true, "/usr/bin/git", "status"),
		at(2, "/sbin/launchd", "", true, "xpcproxy"),
	}
	window := []event.Event{
		at(10, "/bin/zsh", "", true, "/usr/bin/git", "status"),
		at(11, "/bin/zsh", "", true, "/usr/bin/curl", "-fsSL", "http://x"),
		at(12, "/opt/homebrew/bin/brew", "9BNSXJN65R", false, "/tmp/stage.sh"),
		at(13, "/opt/homebrew/bin/brew", "9BNSXJN65R", false, "/tmp/stage.sh"),
	}
	got := NewIn(baseline, window, baseline[0].Time, 20, nil)

	if len(got.Commands) != 2 {
		t.Errorf("commands = %v, want the curl and the stage.sh shapes", keys(got.Commands))
	}

	for _, k := range keys(got.Commands) {
		if k == "/usr/bin/git status" {
			t.Error("a command present in the baseline must not be an arrival")
		}
	}

	want := map[string]bool{"brew": true, "stage.sh": true, "curl": true}
	for _, k := range keys(got.Binaries) {
		if !want[k] {
			t.Errorf("binary %q is not new; baseline held zsh, git and launchd", k)
		}

		delete(want, k)
	}

	if len(want) > 0 {
		t.Errorf("missed arrivals: %v", want)
	}

	if keys(got.Teams)[0] != "9BNSXJN65R" || len(got.Teams) != 1 {
		t.Errorf("teams = %v, want only the new one", keys(got.Teams))
	}

	if got.Baseline != 3 || got.Window != 4 {
		t.Errorf("counts = %d/%d, want 3/4", got.Baseline, got.Window)
	}

	if got.Binaries[0].Count < got.Binaries[len(got.Binaries)-1].Count {
		t.Error("arrivals should be ranked busiest first")
	}
}

func TestNewInEmptyBaseline(t *testing.T) {
	window := []event.Event{at(0, "/bin/zsh", "", true, "/usr/bin/git")}
	got := NewIn(nil, window, time.Time{}, 20, nil)
	if len(got.Binaries) != 2 {
		t.Errorf("with no baseline everything is new, got %v", keys(got.Binaries))
	}
}
