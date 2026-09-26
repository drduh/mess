package classify

import "strings"

const (
	KindAgent     = "agent"     // runs in a user session
	KindApp       = "app"       // main binary of .app bundle
	KindDaemon    = "daemon"    // runs in the background, usually as root
	KindExtension = "extension" // app extension
	KindFramework = "framework" // support binary inside a .framework
	KindHelper    = "helper"    // helper process inside a bundle
	KindTool      = "tool"      // command line program
	KindXPC       = "xpc"       // xpc service
)

var daemonDirs = []string{
	"/sbin/",
	"/usr/sbin/",
	"/usr/libexec/",
	"/System/Library/CoreServices/",
	"/Library/Apple/System/Library/CoreServices/",
}

var toolDirs = []string{
	"/bin/",
	"/usr/bin/",
	"/usr/local/bin/",
	"/usr/local/sbin/",
	"/opt/local/bin/",
	"/opt/homebrew/bin/",
	"/opt/homebrew/sbin/",
	"/opt/homebrew/Cellar/",
}

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
	return strings.HasSuffix(lower, "helper")
}

func hasAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}

	return false
}
