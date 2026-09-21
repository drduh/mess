package classify

import (
	"regexp"
	"strings"
)

const (
	FetchRun         = "fetch and run"
	Disarm           = "security control changed"
	Unquarantine     = "quarantine cleared"
	Inject           = "library injection"
	Startup          = "startup item changed"
	CredentialAccess = "credential access"
	AccountChange    = "account or group changed"
	Evasion          = "history cleared or file hidden"
	Encoded          = "encoded or generated command"
	Killed           = "process killed"
	MakeExec         = "made executable"
	ProfileChange    = "shell profile changed"
	Mount            = "disk image mounted"
)

var (
	fetchers = []string{"curl ", "wget ", "nscurl ", "/curl", "/wget"}

	shellPipes = []string{"| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh",
		"| python", "|python", "| perl", "|perl"}

	disarms = []string{
		"spctl --master-disable", "spctl --global-disable",
		"csrutil disable", "csrutil authenticated-root disable", "bputil",
		"tccutil reset",
		"systemsetup -setremotelogin on",
		"nvram boot-args", "defaults write com.apple.lsquarantine",

		// Firewall, packet filter and sudo policy
		"socketfilterfw --setglobalstate off", "pfctl -d", "pfctl -f ",
		"visudo", "/etc/sudoers",

		// System/kernel extensions
		"kextload", "kmutil load", "kmutil install",
		"systemextensionsctl uninstall", "systemextensionsctl reset",
		"systemextensionsctl developer",
	}

	inspects = []string{
		"systemextensionsctl list", "kmutil showloaded", "kextstat",
		"csrutil status", "spctl --status", "fdesetup status",
		"socketfilterfw --getglobalstate", "pfctl -s", "profiles list",
		"systemsetup -get", "launchctl print-disabled", "nvram -p",
	}

	accountVerbs = []string{
		"dscl . -create", "dscl . -append", "dscl . -passwd", "dscl . -delete", "dscl . -merge",
		"dscl /local/default -create", "dscl /local/default -append", "dscl /local/default -passwd",
		"sysadminctl -adduser", "sysadminctl -deleteuser", "sysadminctl -resetpasswordfor",
		"dseditgroup -o edit", "dseditgroup -o create", "dseditgroup -o delete",
		"/groups/admin", "/groups/wheel",
	}

	evasions = []string{
		"history -c", "unset histfile", "histfile=/dev/null", "histsize=0",
		"chflags hidden", "chflags uchg", "setfile -a v",
	}

	historyFiles = []string{".zsh_history", ".bash_history", ".sh_history", ".python_history"}

	destroyers = []string{"rm ", "unlink ", "truncate ", "shred ", "> ", ": >", ":> "}

	launchVerbs = []string{"load", "unload", "bootstrap", "bootout",
		"enable", "disable", "remove", "submit", "kickstart"}

	startupDirs = []string{"/library/launchagents", "/library/launchdaemons",
		"/library/startupitems", "/etc/periodic", "/var/at/tabs", "/etc/crontab",
		"/library/loginitems", "login item"}

	writers = map[string]bool{
		"cp": true, "mv": true, "ln": true, "tee": true, "install": true,
		"rm": true, "plutil": true, "defaults": true, "crontab": true,
	}

	injected = regexp.MustCompile(
		`(?i)(^|[\s;&])(DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|LD_PRELOAD)=`)

	secrets = []string{
		"security find-generic-password", "security find-internet-password",
		"security dump-keychain", "login.keychain",
		"/.ssh/id_", "/.aws/credentials", "/.netrc",
	}
)

type concernRule struct {
	kind string
	is   func(cmd []string, line string) bool
}

var concernRules = []concernRule{

	// download to pipe
	{FetchRun, func(_ []string, line string) bool {
		return hasAnyOf(line, fetchers) && hasAnyOf(line, shellPipes)
	}},

	// security controls disabled
	{Disarm, func(_ []string, line string) bool { return hasAnyOf(line, disarms) }},

	// quarantine attributes removed
	{Unquarantine, func(cmd []string, line string) bool {
		return strings.Contains(line, "xattr") &&
			(strings.Contains(line, "com.apple.quarantine") || hasFlag(cmd, "-c")) &&
			!hasFlag(cmd, "-l") && !hasFlag(cmd, "-p")
	}},

	{Inject, func(cmd []string, _ string) bool {
		for _, arg := range cmd {
			if injected.MatchString(arg) {
				return true
			}
		}
		return false
	}},

	{Startup, changesStartup},

	{CredentialAccess, func(_ []string, line string) bool { return hasAnyOf(line, secrets) }},

	{AccountChange, func(_ []string, line string) bool {
		return hasAnyOf(line, accountVerbs) &&
			!strings.Contains(line, " -read") && !strings.Contains(line, " -list")
	}},

	// rm on a history file
	{Evasion, func(_ []string, line string) bool {
		return hasAnyOf(line, evasions) || (hasAnyOf(line, historyFiles) && hasAnyOf(line, destroyers))
	}},

	{Encoded, isEncoded},

	{Killed, func(cmd []string, _ string) bool { return killers[Command(cmd[0])] }},

	{MakeExec, func(cmd []string, _ string) bool { return madeExecutable(cmd) }},

	{ProfileChange, changesProfile},

	{Mount, mountsImage},
}

func Concerns(cmd []string) []string {
	if len(cmd) == 0 {
		return nil
	}

	line := strings.ToLower(strings.Join(cmd, " "))
	var out []string
	for _, r := range concernRules {
		if r.is(cmd, line) {
			out = append(out, r.kind)
		}
	}

	return out
}

func madeExecutable(cmd []string) bool {
	if Command(cmd[0]) != "chmod" {
		return false
	}

	for _, a := range cmd[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}

		if strings.Contains(a, "x") && strings.ContainsAny(a, "+=") {
			return true
		}

		if isOctalExec(a) {
			return true
		}

		break
	}

	return false
}

func isOctalExec(mode string) bool {
	if len(mode) < 3 || len(mode) > 4 {
		return false
	}

	for _, r := range mode {
		if r < '0' || r > '7' {
			return false
		}
	}

	// last three digits are owner, group, other. execute is bit 1.
	for _, r := range mode[len(mode)-3:] {
		if (r-'0')&1 == 1 {
			return true
		}
	}
	return false
}

var profiles = []string{
	".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout",
	".bashrc", ".bash_profile", ".bash_login", ".profile",
	"/etc/zshrc", "/etc/zprofile", "/etc/profile", "/etc/paths.d", "/etc/zshenv",
}

var profileWriters = map[string]bool{
	"tee": true, "cp": true, "mv": true, "ln": true, "rm": true, "install": true,
	"sed": true, "perl": true, "awk": true, "python": true, "python3": true, "ruby": true,
	"vim": true, "vi": true, "nano": true, "emacs": true, "ed": true, "code": true,
	"chmod": true, "chown": true, "touch": true, "defaults": true,
}

func changesProfile(cmd []string, line string) bool {
	if !hasAnyOf(line, profiles) {
		return false
	}

	if profileWriters[Command(cmd[0])] {
		return true
	}

	// sh -c 'echo ... >> ~/.zshrc'
	return strings.Contains(line, ">>") || strings.Contains(line, " > ")
}

func mountsImage(cmd []string, line string) bool {
	switch Command(cmd[0]) {
	case "hdiutil":
		return hasAnyOf(line, []string{" attach", " mount"})
	case "open":
		return hasAnyOf(line, []string{".dmg", ".iso", ".sparsebundle", ".sparseimage"})
	case "diskimages-helper", "diskimagecontroller":
		return true
	}

	return hasAnyOf(line, []string{"mount_apfs /dev/disk", "mount -t hfs"})
}

var killers = map[string]bool{"kill": true, "pkill": true, "killall": true}

var decoders = []string{
	"base64 -d", "base64 --decode", "base64 -D", "openssl base64 -d", "openssl enc -d",
	"xxd -r", "uudecode", "| bash", "|bash", "| sh", "|sh", "| zsh",
}

// b64ish reports a token that is long and uniform enough to be an
// encoded payload rather than a path or a flag.
func b64ish(tok string) bool {
	if len(tok) < 120 {
		return false
	}

	for _, r := range tok {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '+', r == '/', r == '=':
		default:
			return false
		}
	}

	return true
}

func isEncoded(cmd []string, line string) bool {
	tool := Command(cmd[0])
	decoded := hasAnyOf(line, decoders[:6])
	piped := hasAnyOf(line, decoders[6:])

	if decoded && piped {
		return true
	}

	if hasAnyOf(line, []string{"eval $(", "eval `", "eval \"$(", "eval $("}) {
		return true
	}

	switch tool {
	case "python", "python3", "perl", "ruby", "node", "osascript", "php":
		if hasFlag(cmd, "-c") || hasFlag(cmd, "-e") {
			if decoded || hasAnyOf(line, []string{
				"exec(", "eval(", "__import__", "fromcharcode", "\\x", "chr("},
			) {
				return true
			}
		}
	}

	for _, tok := range cmd[1:] {
		if b64ish(tok) {
			return true
		}
	}

	return false
}

func changesStartup(cmd []string, line string) bool {
	tool := Command(cmd[0])
	if tool == "launchctl" {
		for _, a := range cmd[1:] {
			for _, v := range launchVerbs {
				if a == v {
					return true
				}
			}
		}

		return false
	}

	if tool == "crontab" {
		return !hasFlag(cmd, "-l")
	}

	if tool == "at" || tool == "batch" {
		return true
	}

	if tool == "osascript" && strings.Contains(line, "login item") {
		return true
	}

	if tool == "defaults" && !hasAnyOf(line, []string{" write ", " delete ", " import ", " rename "}) {
		return false
	}

	if tool == "plutil" && !hasAnyOf(line, []string{" -insert ", " -replace ", " -remove ", " -convert "}) {
		return false
	}

	return writers[tool] && hasAnyOf(line, startupDirs)
}

func hasAnyOf(line string, want []string) bool {
	for _, w := range want {
		if strings.Contains(line, w) {
			return true
		}
	}
	return false
}

func hasFlag(cmd []string, flag string) bool {
	for _, a := range cmd {
		if a == flag {
			return true
		}
	}
	return false
}

func Inspect(cmd []string) bool {
	return hasAnyOf(strings.ToLower(strings.Join(cmd, " ")), inspects)
}
