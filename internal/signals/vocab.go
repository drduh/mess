package signals

import (
	"strings"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
)

const (
	keySymbol = " \u2192 "
	osaScript = "osascript"
	personMin = 501
	personMax = 1 << 31
)

var (
	shells = map[string]bool{
		"sh":   true,
		"bash": true,
		"zsh":  true,
		"dash": true,
		"ksh":  true,
	}

	anyoneWritableAnywhere = []string{"/Downloads/"}
	anyoneWritablePrefixes = []string{
		"/tmp/",
		"/Volumes/",
		"/private/tmp/",
		"/Users/Shared/",
	}

	systemClearedAnywhere = []string{"/Library/Caches/"}
	systemClearedPrefixes = []string{
		"/var/tmp/",
		"/var/folders/",
		"/private/var/tmp/",
		"/private/var/folders/"}
)

func Keyed(from, command string) string {
	return from + keySymbol + command
}

func ImageName(e *event.Event) string {
	return classify.Command(e.Image())
}

func IsPerson(uid uint32) bool {
	return uid >= personMin && uid < personMax
}

func IsShell(name string) bool {
	return shells[name]
}

func under(path string, prefixes, anywhere []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}

	for _, a := range anywhere {
		if strings.Contains(path, a) {
			return true
		}
	}

	return false
}

func AnyoneWritable(path string) bool {
	return under(path, anyoneWritablePrefixes, anyoneWritableAnywhere)
}

func LoosePlace(path string) bool {
	return AnyoneWritable(path) ||
		under(path, systemClearedPrefixes, systemClearedAnywhere)
}

func LooseIn(e *event.Event) string {
	candidates := []string{e.Path, e.Target.Path, e.Script, e.ResolvedArgv0()}
	if a := e.Argv0(); !e.Target.Known() && strings.HasPrefix(a, "/") {
		candidates = append(candidates, a)
	}

	for _, p := range candidates {
		if p != "" && LoosePlace(p) {
			return p
		}
	}

	return ""
}

func commandIn(key string) string {
	if i := strings.Index(key, keySymbol); i >= 0 {
		return key[i+len(keySymbol):]
	}

	return key
}

func findFor(scope, key string) string {
	switch scope {
	case "file":
		return ""
	case "command":
		words := strings.Fields(unwrapShell(commandIn(key)))
		if len(words) > 2 {
			words = words[:2]
		}
		return strings.Join(words, " ")
	}

	return key
}

func ShellPayload(cmd []string) (string, bool) {
	if len(cmd) < 3 {
		return "", false
	}

	name := classify.Command(cmd[0])
	flag := ""

	switch {
	case shells[name]:
		flag = "-c"
	case name == osaScript:
		flag = "-e"
	default:
		return "", false
	}

	for i := 1; i < len(cmd)-1; i++ {
		if cmd[i] == flag {
			return name + " " + flag + " " + cmd[i+1], true
		}
	}

	return "", false
}

func unwrapShell(cmd string) string {
	words := strings.Fields(cmd)
	if len(words) < 3 {
		return cmd
	}

	name := classify.Command(words[0])
	flag := ""

	switch {
	case shells[name]:
		flag = "-c"
	case name == osaScript:
		flag = "-e"
	default:
		return cmd
	}

	if words[1] != flag {
		return cmd
	}

	return strings.Join(words[2:], " ")
}
