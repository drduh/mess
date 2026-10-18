package rules

import (
	"slices"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/signals"
)

var fileRules = slices.Concat(groupWritableSplit.rules(), []signals.Rule{
	{
		ID:      "flagged_file",
		Title:   "Hidden or locked binary",
		Tier:    signals.Alert,
		Scope:   "path",
		Summary: "The file that ran is flagged hidden, or locked against change or deletion.",
		Because: "A few Apple files are flagged; those are left out.",
		Match:   flaggedFile,
	},
	{
		ID:      "world_writable_exec",
		Title:   "Ran a world-writable file",
		Tier:    signals.Alert,
		Scope:   "path",
		Summary: "Any account may write the executed file.",
		Because: "Almost nothing ships this way.",
		Match:   seen(worldWritableExec),
	},
	{
		ID:      "edited_after_arrival",
		Title:   "Changed after it was created",
		Tier:    signals.Notice,
		Scope:   "path",
		Summary: "The file was last written well after it was made.",
		Because: "Editing your own scripts may do this.",
		Match:   editedAfterArrival,
	},
	{
		ID:      "new_file",
		Title:   "Ran soon after it appeared",
		Tier:    signals.Notice,
		Scope:   "path",
		Summary: "The image ran within the threshold of first appearing on this machine.",
		Because: "Builds and unpacked installers may do this.",
		Match:   newFile,
		Measure: func(e event.Event) int { return int(e.Time.Sub(e.Target.Birth).Seconds()) },
		Tune: &signals.Tunable{
			Key:     "new_age",
			Label:   "Ran within",
			Unit:    "seconds",
			Keep:    "below",
			Default: 1800,
			Choices: []int{300, 900, 1800, 3600, 6 * 3600, 12 * 3600, 24 * 3600},
			Note:    "How soon after a file appeared its run is worth a row.",
		},
	},
	{
		ID:      "rosetta",
		Title:   "Intel binary under Rosetta",
		Tier:    signals.Context,
		Scope:   "path",
		Summary: "The image is x86_64, translated to run on Apple silicon.",
		Because: "Older software without a native build may do this.",
		Match:   rosetta,
	},
})

// groupWritableSplit cuts a group-writable file on whether root ran it.
var groupWritableSplit = split{
	key: seen(groupWritableExec),
	by:  func(e *signals.Seen) bool { return e.UID == 0 && e.Target.UID == 0 },
	yes: signals.Rule{
		ID:      "group_writable_root",
		Title:   "Root ran a file its group can rewrite",
		Tier:    signals.Alert,
		Scope:   "path",
		Summary: "Root executed a file any member of its group may write.",
		Because: "The group is often admin, so any administrator can run code as root without a password.",
	},
	no: signals.Rule{
		ID:      "group_writable_exec",
		Title:   "Ran a group-writable file",
		Tier:    signals.Notice,
		Scope:   "path",
		Summary: "Any member of its group may write the executed file.",
		Because: "Shared build directories and team installs may do this.",
	},
}

// newCeiling is the oldest file new_file looks at.
const newCeiling = 24 * time.Hour

// worldWrite is S_IWOTH.
const worldWrite = 0o002

// flaggedFile is the match for flagged_file.
func flaggedFile(e *signals.Seen) string {
	t := &e.Target
	if !t.Known() || t.Sys || t.Flags == 0 {
		return ""
	}

	const hides = classify.UFHidden | classify.UFImmutable | classify.SFImmutable | classify.SFNoUnlink
	if t.Flags&hides == 0 {
		return ""
	}

	return t.Path
}

// editedAfterArrival is the match for edited_after_arrival, with a second of slack.
func editedAfterArrival(e *signals.Seen) string {
	t := &e.Target
	if !t.Known() || t.Sys || t.MTime.IsZero() || t.Birth.IsZero() {
		return ""
	}

	if t.MTime.Sub(t.Birth) <= time.Second {
		return ""
	}

	return t.Path
}

// newFile is the match for new_file.
func newFile(e *signals.Seen) string {
	t := &e.Target
	if !t.Known() || t.Sys || t.Birth.IsZero() || classify.Package(t.Path) != "" {
		return ""
	}

	age := e.Time.Sub(t.Birth)
	if age < 0 || age > newCeiling {
		return ""
	}

	return t.Path
}

// rosetta is the match for rosetta.
func rosetta(e *signals.Seen) string {
	if translated(e.Event) {
		return e.Image()
	}

	return ""
}

// worldWritableExec reports an image any account may rewrite; Mode is only set off the platform.
func worldWritableExec(e *event.Event) string {
	t := &e.Target
	if t.Known() && !t.Sys && t.Mode != 0 && t.Mode&worldWrite != 0 {
		return t.Path
	}

	return ""
}

// groupWritableExec reports an image its group may rewrite, outside the package trees.
func groupWritableExec(e *event.Event) string {
	t := &e.Target
	if !t.Known() || t.Sys || t.Mode == 0 || !classify.PermOf(t.Mode).GroupWritable {
		return ""
	}

	if classify.Package(t.Path) != "" {
		return ""
	}

	return t.Path
}

// translated is an Intel image running under Rosetta.
func translated(e *event.Event) bool { return classify.Arch(e.CPU) == classify.ArchX86_64 }
