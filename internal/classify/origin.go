package classify

import "strings"

func Origin(path string) string {
	if strings.Contains(path, "/System/Applications/") {
		return "sysapps"
	}

	if name, ok := appBundle(path, "/Applications/"); ok {
		return name
	}

	if strings.HasPrefix(path, "/Users/") {
		if i := strings.Index(path, "/Applications/"); i > 0 {
			if name, ok := appBundle(path[i:], "/Applications/"); ok {
				return name
			}
		}
	}

	return ""
}

func Package(path string) string {
	switch {
	case strings.HasPrefix(path, "/opt/homebrew/"),
		strings.HasPrefix(path, "/usr/local/Cellar/"),
		strings.HasPrefix(path, "/usr/local/Homebrew/"):
		return "homebrew"
	case strings.HasPrefix(path, "/nix/"):
		return "nix"
	case strings.HasPrefix(path, "/opt/local/"):
		return "macports"
	}

	return ""
}

func Vendor(path, sign string) string {
	if o := Origin(path); o != "" && o != "sysapps" {
		return o
	}

	if p := Package(path); p != "" {
		return p
	}

	parts := strings.Split(sign, ".")
	if len(parts) >= 3 {
		return strings.ToLower(parts[1])
	}

	if len(parts) == 2 {
		return strings.ToLower(parts[0])
	}

	return ""
}

// appBundle extracts "firefox" out of /Applications/Firefox.app/
func appBundle(path, marker string) (string, bool) {
	if !strings.HasPrefix(path, marker) {
		return "", false
	}

	rest := path[len(marker):]
	end := strings.Index(rest, ".app")
	if end <= 0 {
		return "", false
	}

	name := rest[:end]
	if strings.Contains(name, "/") {
		return "", false
	}

	return strings.ToLower(name), true
}

var systemPrefixes = []string{
	"/bin/",
	"/sbin/",
	"/usr/bin/",
	"/usr/lib/",
	"/usr/libexec/",
	"/usr/sbin/",
	"/usr/share/",
	"/Library/Apple/",
	"/System/",
}

func SystemPrefixes() []string {
	out := make([]string, len(systemPrefixes))
	copy(out, systemPrefixes)
	return out
}
