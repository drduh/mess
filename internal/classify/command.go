package classify

import (
	"path"
	"strings"
)

// Command normalizes argv[0].
func Command(argv0 string) string {
	if argv0 == "" || argv0 == "/" {
		return ""
	}

	return strings.TrimPrefix(path.Base(argv0), "-")
}
