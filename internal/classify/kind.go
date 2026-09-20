package classify

import "strings"

const (
	KindApp       = "app"       // main binary of .app bundle
	KindExtension = "extension" // app extension
	KindXPC       = "xpc"       // xpc service
	KindHelper    = "helper"    // helper process inside a bundle
	KindAgent     = "agent"     // runs in a user session
	KindDaemon    = "daemon"    // runs in the background, usually as root
	KindFramework = "framework" // support binary inside a .framework
	KindTool      = "tool"      // command line program
)

var daemonDirs = []string{"/usr/libexec/", "/usr/sbin/", "/sbin/",
	"/System/Library/CoreServices/", "/Library/Apple/System/Library/CoreServices/"}

var toolDirs = []string{"/usr/bin/", "/bin/", "/opt/homebrew/bin/", "/opt/homebrew/sbin/",
	"/usr/local/bin/", "/usr/local/sbin/", "/opt/local/bin/", "/opt/homebrew/Cellar/"}

func Kind(name, path string) string {
	switch {
	case strings.Contains(path, ".appex/"):
		return KindExtension
	case strings.Contains(path, ".xpc/"):
		return KindXPC
	}

	switch {
	case isHelper(name):
		return KindHelper
	case strings.HasSuffix(name, "Agent") || strings.HasSuffix(name, "agent"):
		return KindAgent
	}

	if strings.Contains(path, ".app/Contents/MacOS/") {
		return KindApp
	}

	if hasAny(path, daemonDirs) {
		return KindDaemon
	}

	if hasAny(path, toolDirs) {
		return KindTool
	}

	if len(name) >= 5 && strings.HasSuffix(name, "d") {
		return KindDaemon
	}

	if strings.Contains(path, ".framework/") {
		return KindFramework
	}

	if strings.Contains(path, "/bin/") {
		return KindTool
	}

	return ""
}

func isHelper(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, "helper") ||
		strings.HasSuffix(lower, "-helper") ||
		strings.HasSuffix(lower, "_helper")
}

func hasAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
