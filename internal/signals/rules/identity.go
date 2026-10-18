package rules

import (
	"strings"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
	"github.com/drduh/mess/internal/signals"
)

var identityRules = []signals.Rule{
	{
		ID:      "path_two_identities",
		Title:   "One path, two signing identities",
		Tier:    signals.Alert,
		Scope:   "path",
		Summary: "The same path ran under signing identities from different developers.",
		Because: "Package manager links and shims may do this.",
		Walk:    pathTwoIdentities,
	},
	{
		ID:      "apple_id_third",
		Title:   "Apple identifier on a non-Apple binary",
		Tier:    signals.Alert,
		Scope:   "path",
		Summary: "The image claims a com.apple.* signing id but is not a platform binary and has no team id.",
		Because: "Apple's own software outside the system volume is signed with a team.",
		Match:   appleIDThird,
	},
	{
		ID:      "same_code_two_paths",
		Title:   "Same code at two paths",
		Tier:    signals.Alert,
		Scope:   "identity",
		Summary: "One code hash ran from two or more paths.",
		Because: "Build output copied into place, or a tool installed twice, may do this.",
		Walk:    sameCodeTwoPaths,
		Find:    sameCodeFind,
	},
	{
		ID:      "adhoc",
		Title:   "Ad-hoc signed, outside the package trees",
		Tier:    signals.Notice,
		Scope:   "path",
		Summary: "The image has no signing identity and is not under Homebrew, MacPorts or nix.",
		Because: "Your own builds may do this.",
		Match:   adhoc,
	},
	{
		ID:      "unsigned_caller",
		Title:   "Unsigned caller",
		Tier:    signals.Notice,
		Scope:   "path",
		Summary: "A binary with no team id called exec.",
		Because: "Homebrew's ruby and local builds may do this.",
		Match:   unsignedCaller,
	},
	{
		ID:      "changed_build",
		Title:   "Binary changed under a familiar signing id",
		Tier:    signals.Notice,
		Scope:   "identity",
		Summary: "One signing id carried two or more code hashes in this window.",
		Because: "Updates and rebuilds may do this.",
		Walk:    changedBuild,
	},
}

// pathTwoIdentities is the walk for path_two_identities.
func pathTwoIdentities(c pids.Capture, emit func(event.Event, string, int)) {
	teams := map[string]map[string]bool{}
	for i := range c.Events {
		t := &c.Events[i].Target
		if !t.Known() || t.Sys || t.Path == "" || t.Team == "" {
			continue
		}

		if teams[t.Path] == nil {
			teams[t.Path] = map[string]bool{}
		}
		teams[t.Path][t.Team] = true
	}

	for i := range c.Events {
		e := &c.Events[i]
		if t := &e.Target; t.Known() && len(teams[t.Path]) > 1 {
			emit(*e, t.Path, 1)
		}
	}
}

// appleIDThird is the match for apple_id_third.
func appleIDThird(e *signals.Seen) string {
	t := &e.Target
	if t.Known() && !t.Sys && t.Team == "" && strings.HasPrefix(t.Sign, "com.apple.") {
		return t.Path
	}

	return ""
}

// sameCodeTwoPaths is the walk for same_code_two_paths, keyed by the code.
func sameCodeTwoPaths(c pids.Capture, emit func(event.Event, string, int)) {
	paths := map[string]map[string]bool{}
	for i := range c.Events {
		t := &c.Events[i].Target
		if !t.Known() || t.CDHash == "" || t.Sys {
			continue
		}

		if paths[t.CDHash] == nil {
			paths[t.CDHash] = map[string]bool{}
		}
		paths[t.CDHash][t.Path] = true
	}

	for i := range c.Events {
		e := &c.Events[i]
		if t := &e.Target; t.Known() && len(paths[t.CDHash]) > 1 {
			emit(*e, classify.Command(t.Path)+" ["+shortHash(t.CDHash)+"]", 1)
		}
	}
}

// adhoc is the match for adhoc.
func adhoc(e *signals.Seen) string {
	t := &e.Target
	if t.Known() && !t.Sys && t.CS&classify.CSAdhoc != 0 && classify.Package(t.Path) == "" {
		return t.Path
	}

	return ""
}

// unsignedCaller is the match for unsigned_caller.
func unsignedCaller(e *signals.Seen) string {
	if !e.Sys && e.Team == "" {
		return e.Path
	}

	return ""
}

// changedBuild is the walk for changed_build.
func changedBuild(c pids.Capture, emit func(event.Event, string, int)) {
	hashes := map[string]map[string]bool{}
	for i := range c.Events {
		t := &c.Events[i].Target
		if !t.Known() || t.Sign == "" || t.CDHash == "" {
			continue
		}

		if hashes[t.Sign] == nil {
			hashes[t.Sign] = map[string]bool{}
		}
		hashes[t.Sign][t.CDHash] = true
	}

	for i := range c.Events {
		e := &c.Events[i]
		if t := &e.Target; t.Known() && len(hashes[t.Sign]) > 1 {
			emit(*e, t.Sign, 1)
		}
	}
}

// shortHash is the first twelve characters of a code hash.
func shortHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}

	return hash
}

// sameCodeFind searches a same_code_two_paths row by the hash head in its key.
func sameCodeFind(key string) string {
	open := strings.LastIndex(key, " [")
	if open < 0 || !strings.HasSuffix(key, "]") {
		return ""
	}

	return "cdhash:" + key[open+2:len(key)-1]
}
