package rules

import (
	"strings"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
	"github.com/drduh/mess/internal/signals"
)

var placeRules = []signals.Rule{
	{
		ID:      "ran_from_loose",
		Title:   "Ran from a writable place",
		Tier:    signals.Alert,
		Scope:   "path",
		Summary: "A program ran from a directory anyone can write to.",
		Because: "Installers and build tools may do this.",
		Match:   ranFromLoose,
	},
	{
		ID:      "script_from_loose",
		Title:   "A script ran from a writable place",
		Tier:    signals.Alert,
		Scope:   "file",
		Summary: "An interpreter ran a script from a directory anyone can write to.",
		Because: "Installers and build tools may do this.",
		Match:   scriptFromLoose,
	},
	{
		ID:      "hidden_path",
		Title:   "Ran from a hidden directory",
		Tier:    signals.Notice,
		Scope:   "path",
		Summary: "A program ran from a path with a dot directory in it, which is hidden in Finder by default.",
		Because: "Developer tools may install under a dot directory.",
		Match:   hiddenPath,
	},
	{
		ID:      "cwd_other_home",
		Title:   "Working in another account",
		Tier:    signals.Notice,
		Scope:   "path",
		Summary: "A process ran with its working directory inside a home that is not the account it ran as.",
		Because: "A system process or administrator backing up, moving or organizing files.",
		Walk:    cwdOtherHome,
	},
	{
		ID:      "writable",
		Title:   "Ran from a writable directory",
		Tier:    signals.Notice,
		Scope:   "path",
		Summary: "A caller, image or script ran from /tmp, /Volumes, /Users/Shared or Downloads.",
		Because: "Installers may use these directories.",
		Match:   seen(signals.LooseIn),
	},
	{
		ID:      "relative_argv0",
		Title:   "Relative argv[0]",
		Tier:    signals.Notice,
		Scope:   "command",
		Summary: "An image was named by a relative path.",
		Because: "Typically run interactively during testing and development.",
		Match:   relativeArgv0,
	},
}

// ranFromLoose is the match for ran_from_loose.
func ranFromLoose(e *signals.Seen) string {
	if e.Target.Known() && e.Target.Sys {
		return ""
	}

	path := e.Image()
	if !signals.LoosePlace(path) {
		return ""
	}

	return path
}

// scriptFromLoose is the match for script_from_loose.
func scriptFromLoose(e *signals.Seen) string {
	if e.Script == "" || !signals.LoosePlace(e.Script) {
		return ""
	}

	return e.Script
}

// hiddenPath is the match for hidden_path.
func hiddenPath(e *signals.Seen) string {
	if e.Target.Known() && e.Target.Sys {
		return ""
	}

	path := e.Image()
	if hiddenPart(path) == "" {
		return ""
	}

	return path
}

// cwdOtherHome is the walk for cwd_other_home.
func cwdOtherHome(c pids.Capture, emit func(event.Event, string, int)) {
	seen := map[uint32]map[string]int{}

	for i := range c.Events {
		e := &c.Events[i]
		if h := homeOf(e.CWD); h != "" {
			if seen[e.UID] == nil {
				seen[e.UID] = map[string]int{}
			}

			seen[e.UID][h]++
		}
	}

	own := map[uint32]string{}
	for uid, homes := range seen {
		best, at, tied := "", 0, false
		for h, n := range homes {
			switch {
			case n > at:
				best, at, tied = h, n, false
			case n == at:
				tied = true
			}
		}

		if !tied {
			own[uid] = best
		}
	}

	for i := range c.Events {
		e := &c.Events[i]
		h := homeOf(e.CWD)
		if h == "" || own[e.UID] == "" || h == own[e.UID] {
			continue
		}

		emit(*e, h, 1)
	}
}

// homeOf is the home directory a path sits under, or "".
func homeOf(path string) string {
	const users = "/Users/"

	if !strings.HasPrefix(path, users) {
		return ""
	}

	rest := path[len(users):]
	name := rest

	if cut := strings.IndexByte(rest, '/'); cut >= 0 {
		name = rest[:cut]
	}

	if name == "" || name == "Shared" {
		return ""
	}

	return users + name
}

// hiddenPart says whether the file or any directory in the path
// begins with a dot.
func hiddenPart(path string) string {
	for i := 0; i < len(path); {
		j := strings.IndexByte(path[i:], '/')

		end := len(path)
		if j >= 0 {
			end = i + j
		}

		if end-i > 1 && path[i] == '.' {
			return path[i:end]
		}

		if j < 0 {
			break
		}

		i = end + 1
	}

	return ""
}

// relativeArgv0 is the match for relative_argv0.
func relativeArgv0(e *signals.Seen) string {
	if a := e.Argv0(); isRelative(a) {
		return a
	}
	return ""
}

func isRelative(argv0 string) bool {
	if argv0 == "" || strings.HasPrefix(argv0, "/") {
		return false
	}

	return strings.Contains(argv0, "/")
}
