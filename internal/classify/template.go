package classify

import (
	"regexp"
	"strings"
)

type rewrite struct {
	re    *regexp.Regexp
	to    func(match string) string
	needs func(s string, hasDigit bool) bool
}

var (
	addr    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)
	digits  = regexp.MustCompile(`\d{3,}`)
	dotted  = regexp.MustCompile(`\b\d+(\.\d+){1,3}\b`)
	hexRun  = regexp.MustCompile(`(?i)\b[0-9a-f]{12,}\b`)
	isoDate = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b`)
	tmpDir  = regexp.MustCompile(`/var/folders/[A-Za-z0-9_]{2}/[A-Za-z0-9_]+/`)
	uuid    = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

var rewrites = []rewrite{
	{tmpDir, word("/var/folders/<tmp>/"),
		func(s string, _ bool) bool { return strings.Contains(s, "/var/folders/") }},
	{uuid, word("<uuid>"),
		func(s string, _ bool) bool { return len(s) >= 36 && strings.Contains(s, "-") }},
	{isoDate, word("<date>"),
		func(s string, d bool) bool { return d && len(s) >= 10 && strings.Contains(s, "-") }},
	{hexRun, func(m string) string {
		if strings.Trim(m, "0123456789") == "" {
			return "<num>"
		}
		return "<hex>"
	}, func(s string, _ bool) bool { return len(s) >= 12 }},
	{dotted, word("<num>"),
		func(s string, d bool) bool { return d && strings.Contains(s, ".") }},
	{digits, word("<num>"),
		func(_ string, d bool) bool { return d }},
}

func word(w string) func(string) string { return func(string) string { return w } }

func Template(cmd []string) string {
	if len(cmd) == 0 {
		return ""
	}

	if len(cmd) == 1 {
		return normalise(cmd[0])
	}

	var out strings.Builder
	for i, arg := range cmd {
		if i > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(normalise(arg))
	}

	return out.String()
}

func normalise(s string) string {
	if !strings.Contains(s, ".") || !strings.ContainsAny(s, "0123456789") {
		return shape(s)
	}

	spans := addr.FindAllStringIndex(s, -1)
	if len(spans) == 0 {
		return shape(s)
	}

	var out strings.Builder
	at := 0
	for _, sp := range spans {
		out.WriteString(shape(s[at:sp[0]]))
		out.WriteString(s[sp[0]:sp[1]])
		at = sp[1]
	}
	out.WriteString(shape(s[at:]))

	return out.String()
}

func shape(s string) string {
	hasDigit := strings.ContainsAny(s, "0123456789")

	for _, r := range rewrites {
		if r.needs(s, hasDigit) {
			s = r.re.ReplaceAllStringFunc(s, r.to)
		}
	}

	return s
}
