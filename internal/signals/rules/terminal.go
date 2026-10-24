package rules

import (
	"slices"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/signals"
)

var clipTools = map[string]bool{
	"pbcopy":  true,
	"pbpaste": true,
}

var fetchTools = map[string]bool{
	"nc":     true,
	"wget":   true,
	"curl":   true,
	"nscurl": true,
}

// interpreters take code on the command line.
var interpreters = map[string]string{
	"perl":      "-e",
	"ruby":      "-e",
	"node":      "-e",
	"swift":     "-e",
	"python":    "-c",
	"python3":   "-c",
	"osascript": "-e",
}

var terminalRules = slices.Concat(
	inlineCodeSplit.rules(),
	clipboardSplit.rules(),
	[]signals.Rule{
		{
			ID:      "unattended_fetch",
			Title:   "Download with no terminal attached",
			Tier:    signals.Notice,
			Scope:   "command",
			Summary: "curl, wget or nc ran without a controlling terminal and the caller was not Apple's.",
			Because: "Scheduled updaters and build scripts may fetch resources.",
			Match:   unattendedFetch,
		},
		{
			ID:      "screen_scripted",
			Title:   "Screen captured",
			Tier:    signals.Notice,
			Scope:   "command",
			Summary: "screencapture ran without a terminal attached.",
			Because: "Automation or a tool taking a picture of the screen.",
			Match:   screenScripted,
		},
	},
)

// inlineCodeSplit is inline interpreter code, cut on a terminal.
var inlineCodeSplit = split{
	key: func(e *signals.Seen) string { return interpreterCode(e.Cmd) },
	by:  untyped,
	yes: signals.Rule{
		ID:      "inline_code_untyped",
		Title:   "Inline interpreter code, no terminal",
		Tier:    signals.Alert,
		Scope:   "command",
		Summary: "Code was handed to python, perl, ruby, node or osascript on the command line with no terminal attached.",
		Because: "Build steps and launch agents may do this.",
	},
	no: signals.Rule{
		ID:      "inline_code",
		Title:   "Inline interpreter code",
		Tier:    signals.Notice,
		Scope:   "command",
		Summary: "Code handed to an interpreter on the command line, typed at a terminal.",
		Because: "A one-liner at a prompt.",
	},
}

// clipboardSplit is pbcopy and pbpaste, cut on a terminal.
var clipboardSplit = split{
	key: func(e *signals.Seen) string {
		if clipTools[signals.ImageName(e.Event)] {
			return line(e.Event)
		}
		return ""
	},
	by: untyped,
	yes: signals.Rule{
		ID:      "clipboard_untyped",
		Title:   "Clipboard read or written with no terminal",
		Tier:    signals.Alert,
		Scope:   "command",
		Summary: "pbcopy or pbpaste ran without a controlling terminal.",
		Because: "Editors and automation use the pasteboard.",
	},
	no: signals.Rule{
		ID:      "clipboard",
		Title:   "Clipboard read or written",
		Tier:    signals.Notice,
		Scope:   "command",
		Summary: "pbcopy or pbpaste at a terminal.",
		Because: "Moving text in and out of a shell.",
	},
}

// unattendedFetch is the match for unattended_fetch.
func unattendedFetch(e *signals.Seen) string {
	if e.TTY != "" || e.Sys || !fetchTools[signals.ImageName(e.Event)] {
		return ""
	}

	if curlUploadTo(e.Event) != "" || wgetUploadTo(e.Event) != "" {
		return ""
	}

	return line(e.Event)
}

// screenScripted is the match for screen_scripted.
func screenScripted(e *signals.Seen) string {
	if e.TTY == "" && signals.ImageName(e.Event) == "screencapture" {
		return line(e.Event)
	}

	return ""
}

// interpreterCode is inline code handed to an interpreter.
func interpreterCode(cmd []string) string {
	if len(cmd) < 3 {
		return ""
	}

	name := classify.Command(cmd[0])

	flag, ok := interpreters[name]
	if !ok {
		return ""
	}

	for i := 1; i < len(cmd)-1; i++ {
		if cmd[i] == flag {
			return name + " " + flag + " " + cmd[i+1]
		}
	}

	return ""
}
