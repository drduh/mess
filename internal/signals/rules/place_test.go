package rules

import (
	"testing"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
	"github.com/drduh/mess/internal/signals"
)

func TestLooseNamesTheWritablePlace(t *testing.T) {
	rule := ruleByID(t, "ran_from_loose")
	cases := []struct {
		path string
		sys  bool
		want bool
	}{
		{"/usr/bin/git", false, false},
		{"/tmp/installer", false, true},
		{"/opt/homebrew/bin/jq", false, false},
		{"/Volumes/Installer/app", false, true},
		{"/Users/admin/Downloads/setup", false, true},
		{"/Users/admin/Library/Caches/thing", false, true},
		{"/private/var/folders/qh/T/AppTranslocation/x", true, false},
		{"/private/var/folders/qh/T/go-build1/exe/stance", false, true},
	}

	for _, c := range cases {
		e := event.Event{Cmd: []string{c.path}, Target: event.Target{Path: c.path, Sys: c.sys}}
		if got := rule.Match(&signals.Seen{Event: &e}) != ""; got != c.want {
			t.Errorf("%s (sys=%v): matched %v, want %v", c.path, c.sys, got, c.want)
		}
	}
}

func TestLooseRowCarriesTheWritableMark(t *testing.T) {
	for _, path := range []string{
		"/tmp/installer",
		"/Users/Shared/thing",
		"/private/var/tmp/thing",
		"/Users/admin/Downloads/tool",
		"/Users/admin/Library/Caches/thing",
		"/var/folders/xy/abc/T/go-build1/b001/exe/helper",
	} {
		e := event.Event{
			Time: minute(1), PID: 500, PPID: 400, UID: 501,
			Path: "/bin/zsh", Sign: "com.apple.zsh", Sys: true,
			Cmd:    []string{path},
			Target: event.Target{Path: path, UID: 501, CDHash: "abc"},
		}

		row := signal(signals.Build(All,
			pids.Over([]event.Event{e}), minute(0), minute(5), 8), "ran_from_loose")
		if row.Count != 1 {
			t.Errorf("%s: ran_from_loose did not fire", path)
			continue
		}

		marked := false
		for _, m := range row.Rows[0].Marks {
			if m == "writable" {
				marked = true
			}
		}

		if !marked {
			t.Errorf("%s: in the writable-place box carrying %v, without the writable mark",
				path, row.Rows[0].Marks)
		}
	}
}

func TestScriptFromLoose(t *testing.T) {
	events := []event.Event{
		{Time: at(1), UID: 501, Path: "/bin/zsh", Script: "/tmp/install.sh",
			Cmd: []string{"/usr/bin/env", "bash"}, Target: event.Target{Path: "/usr/bin/env", Sys: true}},
		{Time: at(2), UID: 501, Path: "/bin/zsh", Script: "/Users/a/src/build.sh",
			Cmd: []string{"/usr/bin/env", "bash"}, Target: event.Target{Path: "/usr/bin/env", Sys: true}},
		{Time: at(3), UID: 501, Path: "/bin/zsh", Cmd: []string{"ls"},
			Target: event.Target{Path: "/bin/ls", Sys: true}},
	}

	list := signals.Build(All, pids.Over(events), at(0), at(4), 4)

	s := signals.ByID(list, "script_from_loose")
	if s == nil || s.Count != 1 {
		t.Fatalf("script_from_loose = %+v, want the one in /tmp", s)
	}

	if s.Rows[0].Key != "/tmp/install.sh" {
		t.Errorf("row names %q; the finding is the script, not the interpreter", s.Rows[0].Key)
	}
}

// Test first dot directory that is not . or ..
func TestHiddenPart(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{".", ""},
		{"/", ""},
		{"/a/./b", ""},
		{"/.a/.b", ".a"},
		{"/a/../b", ".."},
		{"/a/b/.x", ".x"},
		{"/usr/bin/ls", ""},
		{"trailing/.y/", ".y"},
		{"no-slashes-at-all", ""},
		{".hidden/thing", ".hidden"},
		{"/Users/a/.cargo/bin/rg", ".cargo"},
	} {
		if got := hiddenPart(c.in); got != c.want {
			t.Errorf("hiddenPart(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCwdInAnotherHome(t *testing.T) {
	events := []event.Event{
		{Time: at(2), UID: 501, Path: "/bin/zsh", CWD: "/Users/a", Cmd: []string{"ls"},
			Target: event.Target{Path: "/bin/ls", Sys: true}},
		{Time: at(3), UID: 501, Path: "/bin/zsh", CWD: "/Users/b/Documents", Cmd: []string{"ls"},
			Target: event.Target{Path: "/bin/ls", Sys: true}},
		{Time: at(4), UID: 501, Path: "/bin/zsh", CWD: "/Users/Shared/box", Cmd: []string{"ls"},
			Target: event.Target{Path: "/bin/ls", Sys: true}},
		{Time: at(1), UID: 501, Path: "/bin/zsh",CWD: "/Users/a/src", Cmd: []string{"ls"},
			Target: event.Target{Path: "/bin/ls", Sys: true}},
		{Time: at(5), UID: 502, Path: "/bin/zsh", CWD: "/Users/b/src", Cmd: []string{"ls"},
			Target: event.Target{Path: "/bin/ls", Sys: true}},
	}

	list := signals.Build(All, pids.Over(events), at(0), at(6), 6)

	s := signals.ByID(list, "cwd_other_home")
	if s == nil || s.Count != 1 || s.Rows[0].Key != "/Users/b" {
		t.Errorf("cwd_other_home = %+v, want 501 in /Users/b once", s)
	}
}

func TestCwdTieSaysNothing(t *testing.T) {
	events := []event.Event{
		{Time: at(1), UID: 501, Path: "/bin/zsh", CWD: "/Users/a/src", Cmd: []string{"ls"},
			Target: event.Target{Path: "/bin/ls", Sys: true}},
		{Time: at(2), UID: 501, Path: "/bin/zsh", CWD: "/Users/b/src", Cmd: []string{"ls"},
			Target: event.Target{Path: "/bin/ls", Sys: true}},
	}

	for i := 0; i < 20; i++ {
		if s := signals.ByID(signals.Build(All,
			pids.Over(events), at(0), at(3), 3), "cwd_other_home"); s.Count != 0 {
			t.Fatalf("a tie must say nothing, got %+v", s.Rows)
		}
	}
}
