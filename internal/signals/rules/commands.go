package rules

import (
	"slices"
	"strings"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/signals"
)

var (
	controlSwitches = []string{
		"remote-debugging-port",
		"remote-debugging-pipe",
		"start-debugger-server",
		"load-extension",
		"marionette"}

	promptWords = []string{
		"administrator privileges",
		"administratorprivileges",
		"hidden answer",
		"hiddenanswer"}
)

var commandsRules = slices.Concat(
	madeExecSplit.rules(),
	promptSplit.rules(),
	browserSplit.rules(),
	[]signals.Rule{
		{
			ID:      "monitor_killed",
			Title:   "The monitor was signalled",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Something sent a signal to eslogger or to mess.",
			Because: "Stopping the capture or uninstalling mess.",
			Match:   monitorKilled,
		},
		{
			ID:      "fetch_run",
			Title:   "Fetch and run",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Something was downloaded and piped into a shell.",
			Because: "Command line installers or possible social engineering.",
			Match:   concern(classify.FetchRun),
		},
		{
			ID:      "disarm",
			Title:   "Security control changed",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Gatekeeper, SIP, TCC, firewall, sudoers, authorization db or remote login was disabled, reset or changed.",
			Because: "Local testing or software development.",
			Match:   concern(classify.Disarm),
		},
		{
			ID:      "trust_changed",
			Title:   "Certificate trust or traffic routing changed",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Certificate trust, the system proxy, DNS servers, hosts file or resolver was changed.",
			Because: "Device management, VPN clients and local development.",
			Match:   concern(classify.TrustChange),
		},
		{
			ID:      "config_profile",
			Title:   "Configuration profile changed",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Configuration profile was installed or removed with the profiles tool, or a .mobileconfig file.",
			Because: "Device management enrollment for organization-owned systems.",
			Match:   concern(classify.ConfigProfile),
		},
		{
			ID:      "inject",
			Title:   "Library injection",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Library was forced into another process through DYLD or LD_PRELOAD.",
			Because: "Debuggers and profilers may do this.",
			Match:   concern(classify.Inject),
		},
		{
			ID:      "reverse_shell",
			Title:   "Shell wired to a network socket",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Command connected a shell input and output to a network endpoint.",
			Because: "Classic reverse shell.",
			Match:   reverseShell,
		},
		{
			ID:      "unquarantine",
			Title:   "Quarantine cleared",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Quarantine flag was removed, Gatekeeper will not check file.",
			Because: "Running own builds.",
			Match:   concern(classify.Unquarantine),
		},
		{
			ID:      "secrets",
			Title:   "Credential access",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "A keychain, SSH key or credential file was read.",
			Because: "Most often own tooling.",
			Match:   concern(classify.CredentialAccess),
		},
		{
			ID:      "startup",
			Title:   "Startup item changed",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "A launchd job, cron entry, or login item was added, removed or changed.",
			Because: "Software installation adding background services.",
			Join:    "job",
			Match:   concern(classify.Startup),
		},
		{
			ID:      "accounts",
			Title:   "Account or group changed",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "A user or group was created, deleted, given a password or added to a group.",
			Because: "Setting up a new machine or local user.",
			Match:   concern(classify.AccountChange),
		},
		{
			ID:      "evasion",
			Title:   "History cleared or file hidden",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Shell history was deleted or disabled, or a file was made invisible.",
			Because: "History for privacy.",
			Match:   concern(classify.Evasion),
		},
		{
			ID:      "encoded",
			Title:   "Encoded or generated command",
			Tier:    signals.Alert,
			Scope:   "command",
			Summary: "Text was decoded into a shell, code was handed to an interpreter inline, or an argument is a blob.",
			Because: "Build systems and installers might do this.",
			Match:   concern(classify.Encoded),
		},
		{
			ID:      "posture_read",
			Title:   "Security settings inspected",
			Tier:    signals.Notice,
			Scope:   "command",
			Summary: "Probing which protections are on, or what is installed.",
			Because: "Potential recon or new machine setup.",
			Match:   postureRead,
		},
		{
			ID:      "profile_change",
			Title:   "Shell profile modified",
			Tier:    signals.Notice,
			Scope:   "command",
			Summary: "Login shell file was written: .zshrc, .zprofile, .bash_profile and the rest.",
			Because: "Setting up a machine, and every tool that offers to add itself to PATH.",
			Match:   concern(classify.ProfileChange),
		},
		{
			ID:      "mounted",
			Title:   "Disk image mounted",
			Tier:    signals.Notice,
			Scope:   "command",
			Summary: "A disk image (dmg or similar) was attached.",
			Because: "Software installation outside App Store.",
			Match:   concern(classify.Mount),
		},
		{
			ID:      "killed",
			Title:   "Process killed",
			Tier:    signals.Notice,
			Scope:   "command",
			Summary: "kill, pkill or killall was run.",
			Because: "Restarting wedged process, build script tidy.",
			Match:   concern(classify.Killed),
		},
		{
			ID:      "inline_shell",
			Title:   "Inline shell commands",
			Tier:    signals.Context,
			Scope:   "command",
			Summary: "Every sh -c and osascript -e payload.",
			Because: "Build systems and shell scripts are made of these.",
			Match:   inlineShell,
		},
	},
)

// madeExecSplit is chmod +x, cut on a writable directory.
var madeExecSplit = split{
	key: func(e *signals.Seen) string {
		if hasConcern(e, classify.MakeExec) {
			return line(e.Event)
		}

		return ""
	},

	by: func(e *signals.Seen) bool { return looseArg(e.Cmd) != "" },
	yes: signals.Rule{
		ID:      "made_exec_loose",
		Title:   "Made executable in a writable directory",
		Tier:    signals.Alert,
		Scope:   "command",
		Summary: "chmod added the execute bit to something under /tmp, /Volumes, /Users/Shared or Downloads.",
		Because: "Unpacking a build or a manual installer run.",
	},
	no: signals.Rule{
		ID:      "made_exec",
		Title:   "Made executable",
		Tier:    signals.Notice,
		Scope:   "command",
		Summary: "chmod added the execute bit somewhere other than a writable directory.",
		Because: "Known authored or downloaded scripts.",
	},
}

// monitorKilled is the match for monitor_killed.
func monitorKilled(e *signals.Seen) string {
	name := classify.Command(e.Image())
	if name != "kill" && name != "pkill" && name != "killall" {
		return ""
	}

	for _, arg := range args(e.Cmd) {
		if strings.Contains(arg, "eslogger") ||
			classify.Command(arg) == "mess" || arg == "mess" {
			return e.Template()
		}
	}

	return ""
}

// reverseShell is the match for reverse_shell.
func reverseShell(e *signals.Seen) string {
	return reverseShellLine(e.Cmd)
}

// postureRead is the match for posture_read.
func postureRead(e *signals.Seen) string {
	if !classify.Inspect(e.Cmd) {
		return ""
	}

	return e.Template()
}

// inlineShell is the match for inline_shell.
func inlineShell(e *signals.Seen) string {
	payload, _ := signals.ShellPayload(e.Cmd)
	return payload
}

// concern adapts one classify.Concerns kind into a rule matcher.
func concern(kind string) func(*signals.Seen) string {
	return func(e *signals.Seen) string {
		for _, k := range e.Concerns() {
			if k == kind {
				return line(e.Event)
			}
		}

		return ""
	}
}

// hasConcern reports one classify kind on an event.
func hasConcern(e *signals.Seen, kind string) bool {
	for _, k := range e.Concerns() {
		if k == kind {
			return true
		}
	}

	return false
}

// looseArg is the first argument that names a path anyone can write to.
func looseArg(cmd []string) string {
	for _, a := range args(cmd) {
		if signals.AnyoneWritable(a) {
			return a
		}
	}

	return ""
}

// args is argv without argv[0], empty if there is none.
func args(cmd []string) []string {
	if len(cmd) < 2 {
		return nil
	}

	return cmd[1:]
}

// reverseShellLine reports a shell wired to a network socket.
func reverseShellLine(cmd []string) string {
	if len(cmd) == 0 {
		return ""
	}

	name := classify.Command(cmd[0])

	var joined string

	if signals.IsShell(name) || name == "nc" || name == "ncat" || name == "socat" {
		joined = strings.Join(cmd, " ")
	} else if p, ok := signals.ShellPayload(cmd); ok {
		joined = p
	} else {
		return ""
	}

	net := strings.Contains(joined, "/dev/tcp/") ||
		strings.Contains(joined, "/dev/udp/")

	ncShell := (strings.Contains(joined, "nc ") ||
		strings.Contains(joined, "ncat ") ||
		strings.Contains(joined, "socat ")) && (strings.Contains(joined, "-e ") ||
		strings.Contains(joined, "exec:") ||
		strings.Contains(joined, "mkfifo"))

	redirected := net && (strings.Contains(joined, ">&") ||
		strings.Contains(joined, "<&") ||
		strings.Contains(joined, "0>&") ||
		strings.Contains(joined, "|"))

	interactive := strings.Contains(joined, " -i") ||
		strings.Contains(joined, "sh -i") ||
		strings.Contains(joined, "bash -i") ||
		strings.Contains(joined, "zsh -i")

	if (redirected && interactive) || ncShell {
		return joined
	}

	return ""
}

// promptSplit is a script asking for a password, cut on who keeps what is typed.
var promptSplit = split{
	key: seen(passwordPrompt),
	by:  func(e *signals.Seen) bool { return keepsTheAnswer(e.Event) },
	yes: signals.Rule{
		ID:      "password_dialog",
		Title:   "A script drew its own password dialog",
		Tier:    signals.Alert,
		Scope:   "command",
		Summary: "Code handed to osascript presented dialog with a hidden answer field.",
		Because: "Management scripts or password pipe into sudo -S.",
	},
	no: signals.Rule{
		ID:      "admin_prompt",
		Title:   "A script asked for administrator rights",
		Tier:    signals.Notice,
		Scope:   "command",
		Summary: "A script asked macOS for an administrator password.",
		Because: "Installers and helper setup.",
	},
}

// passwordPrompt is an osascript asking for a password.
func passwordPrompt(e *event.Event) string {
	if executesWithPrivileges(e) {
		return line(e)
	}

	text, ok := promptText(e)
	if !ok {
		return ""
	}

	for _, w := range promptWords {
		if strings.Contains(text, w) {
			return line(e)
		}
	}

	return ""
}

// keepsTheAnswer is whether the prompt is the script's own dialog.
func keepsTheAnswer(e *event.Event) bool {
	text, ok := promptText(e)
	return ok && (strings.Contains(text, "hidden answer") ||
		strings.Contains(text, "hiddenanswer"))
}

// promptText is osascript arguments, folded as AppleScript reads them.
func promptText(e *event.Event) (string, bool) {
	if len(e.Cmd) < 2 || signals.ImageName(e) != "osascript" {
		return "", false
	}

	return strings.Join(strings.Fields(strings.ToLower(
		strings.Join(e.Cmd[1:], " "))), " "), true
}

// executesWithPrivileges is security execute-with-privileges.
func executesWithPrivileges(e *event.Event) bool {
	if len(e.Cmd) < 2 || signals.ImageName(e) != "security" {
		return false
	}

	for i := 1; i < len(e.Cmd); i++ {
		a := e.Cmd[i]
		switch {
		case a == "--":
			return i+1 < len(e.Cmd) && e.Cmd[i+1] == "execute-with-privileges"
		case len(a) > 1 && a[0] == '-':
			if j := strings.IndexByte(a, 'p'); j == len(a)-1 {
				i++
			}
		default:
			return a == "execute-with-privileges"
		}
	}

	return false
}

// browserSplit is a browser handed to another program, cut on its profile.
var browserSplit = split{
	key: seen(browserKey),
	by:  func(e *signals.Seen) bool { return !ownProfile(e.Cmd) },
	yes: signals.Rule{
		ID:      "browser_profile_exposed",
		Title:   "Browser profile opened to remote control",
		Tier:    signals.Alert,
		Scope:   "command",
		Summary: "Browser was started with a debugging port or pipe, WebDriver control or an unpacked extension.",
		Because: "Nothing that tests or debugs a browser should justify this.",
		Find:    browserControlFind,
	},
	no: signals.Rule{
		ID:      "browser_debug",
		Title:   "A browser started for testing or debugging",
		Tier:    signals.Context,
		Scope:   "command",
		Summary: "Browser was started with a debugging port or pipe, WebDriver control or an unpacked extension.",
		Because: "Test frameworks, JavaScript debuggers and extension development start browsers this way.",
		Find:    browserControlFind,
	},
}

// browserKey is the browser name plus its control switches, sorted.
func browserKey(e *event.Event) string {
	if !browserControlled(e) {
		return ""
	}

	var given []string

	for _, a := range e.Cmd[1:] {
		if slices.Contains(controlSwitches, switchName(a)) {
			flag, _, _ := strings.Cut(a, "=")
			given = append(given, flag)
		}
	}

	slices.Sort(given)

	return classify.Command(
		e.Image()) + " " + strings.Join(slices.Compact(given), " ")
}

// browserControlled is a browser starting with a control switch.
func browserControlled(e *event.Event) bool {
	if len(e.Cmd) < 2 {
		return false
	}

	control := false

	for _, a := range e.Cmd[1:] {
		switch name := switchName(a); {
		case name == "type":
			return false
		case slices.Contains(controlSwitches, name):
			control = true
		}
	}

	if !control {
		return false
	}

	image := e.Image()

	return classify.Category(
		classify.Command(image), image, e.Target.Sign) == classify.CatBrowser
}

// ownProfile is whether the browser was given its own profile.
func ownProfile(cmd []string) bool {
	for _, a := range cmd {
		switch switchName(a) {
		case "user-data-dir", "profile", "P":
			return true
		}
	}

	return false
}

// switchName is an argument switch without dashes or value.
func switchName(a string) string {
	if len(a) < 2 || a[0] != '-' {
		return ""
	}

	name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")

	return name
}

// browserControlFind searches by the first switch in the key.
func browserControlFind(key string) string {
	for _, s := range controlSwitches {
		if strings.Contains(key, s) {
			return s
		}
	}

	return key
}
