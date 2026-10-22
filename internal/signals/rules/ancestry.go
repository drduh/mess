package rules

import (
	"strings"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
	"github.com/drduh/mess/internal/signals"
)

var ancestryRules = []signals.Rule{
	{
		ID:      "responsible_opener",
		Title:   "A browser or mail client is answerable for a shell",
		Tier:    signals.Alert,
		Scope:   "command",
		Summary: "The process macOS holds responsible for this shell or interpreter is a browser, a mail client or a document application, though nothing in its ancestry is.",
		Because: "An application asking the system to run something on its behalf is ordinary; asking it to run a shell is not.",
		Walk:    responsibleOpener,
	},
	{
		ID:      "opener_descent",
		Title:   "A chain under a browser, mail or document app",
		Tier:    signals.Alert,
		Scope:   "command",
		Summary: "A shell or an interpreter ran two or more steps below a browser, a mail client or a document application, outside that application, with nobody at a terminal.",
		Because: "An installer run from a download and a build launched from an editor both look like this; so does a macro or an attachment that has just been opened.",
		Walk:    openerDescent,
	},
	{
		ID:      "app_shell",
		Title:   "App ran a shell command",
		Tier:    signals.Notice,
		Scope:   "command",
		Summary: "A GUI application ran sh -c or osascript -e.",
		Because: "Update checks and helper scripts.",
		Match:   appShell,
	},
	{
		ID:      "outlived_its_parent",
		Title:   "Ran after the process that forked it had gone",
		Tier:    signals.Notice,
		Scope:   "command",
		Summary: "Endpoint Security recorded a different original parent from the current one: the process that forked this one had already exited.",
		Because: "Every daemoniser does this deliberately, and a script that backgrounds work and returns does it by accident.",
		Match:   outlivedItsParent,
	},
}

// responsibleOpener is the walk for responsible_opener.
func responsibleOpener(c pids.Capture, emit func(event.Event, string, int)) {
	for i := range c.Events {
		e := &c.Events[i]
		if e.RPID == 0 || e.RPID == e.PID || e.TTY != "" {
			continue
		}

		if !spawned[signals.ImageName(e)] {
			continue
		}

		who := c.Index.At(e.RPID, e.Time, nil)
		if who == nil {
			continue
		}

		if !openers[classify.Category(who.Name, who.Path, "")] {
			continue
		}

		emit(*e, signals.Keyed(who.Name, classify.Template(e.Cmd)), 1)
	}
}

// openerDescent is the walk for opener_descent.
func openerDescent(c pids.Capture, emit func(event.Event, string, int)) {
	const depth = 4

	for i := range c.Events {
		e := &c.Events[i]
		if e.TTY != "" {
			continue
		}

		if calledFromApp(e) {
			continue
		}

		if !spawned[classify.Command(e.Image())] {
			continue
		}

		p := c.Index.At(e.PID, e.Time, nil)
		if p == nil {
			continue
		}

		for _, up := range ancestry(c.Index, p, depth) {
			if !openers[c.Cache.Category(up.Name, up.Path, "")] {
				continue
			}

			if inSameBundle(up.Path, e.Image()) {
				break // application's own helper, in its own bundle
			}

			emit(*e, signals.Keyed(up.Name, line(e)), 1)
			break
		}
	}
}

// appShell is the match for app_shell.
func appShell(e *signals.Seen) string {
	if !calledFromApp(e.Event) {
		return ""
	}

	switch e.CallerCategory() {
	case classify.CatTerminal, classify.CatDeveloper:
		return ""
	}

	if payload, ok := signals.ShellPayload(e.Cmd); ok {
		return signals.Keyed(classify.Command(e.Path), payload)
	}

	return ""
}

// outlivedItsParent is the match for outlived_its_parent.
func outlivedItsParent(e *signals.Seen) string {
	if orphaned(e.Event) == 0 || e.Target.Sys {
		return ""
	}

	return classify.Template(e.Cmd)
}

// calledFromApp is whether the caller was an app's own executable.
func calledFromApp(e *event.Event) bool {
	return strings.Contains(e.Path, ".app/Contents/MacOS/")
}

// openers are categories that open outside documents, mail or pages.
var openers = map[string]bool{
	classify.CatBrowser:      true,
	classify.CatComms:        true,
	classify.CatProductivity: true,
}

// spawned are shells and interpreters.
var spawned = map[string]bool{
	"sh": true,
	"zsh": true,
	"ksh": true,
	"bash": true,
	"fish": true,
	"dash": true,
	"perl": true,
	"ruby": true,
	"node": true,
	"curl": true,
	"wget": true,
	"python": true,
	"python3": true,
	"osascript": true,
}

// ancestry walks a process up to the root, nearest first, and stops at the depth given.
func ancestry(idx pids.Index, p *pids.Process, depth int) []*pids.Process {
	var out []*pids.Process

	for i := 0; i < depth && p != nil; i++ {
		up := idx.At(p.PPID, p.First, p, func(cand *pids.Process) bool {
			return pids.CouldHaveForked(cand, p)
		})

		if up == nil {
			return out
		}

		out = append(out, up)
		p = up
	}

	return out
}

// inSameBundle says the two paths belong to one application.
func inSameBundle(ancestor, child string) bool {
	outer := classify.Bundles(ancestor)
	if len(outer) == 0 {
		return false
	}

	return strings.HasPrefix(child, outer[0].Path+"/")
}

// orphaned is the forking pid, if it had already exited.
func orphaned(e *event.Event) int {
	if e.OPPID != 0 && e.OPPID != e.PPID {
		return e.OPPID
	}

	return 0
}
