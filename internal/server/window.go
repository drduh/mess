// Reading and validating the time window for requests.
package server

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxDays   = 36525
	maxWindow = time.Duration(maxDays) * 24 * time.Hour
)

var dayPrefix = regexp.MustCompile(`^(\d+)d(.*)$`)

// parseWindow reads a Go duration, extended with a leading day count.
func parseWindow(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "all" {
		return 0, nil
	}

	var total time.Duration
	rest := raw
	if m := dayPrefix.FindStringSubmatch(rest); m != nil {
		days, err := strconv.Atoi(m[1])
		if err != nil || days > maxDays {
			return 0, badWindow(raw)
		}
		total = time.Duration(days) * 24 * time.Hour
		rest = m[2]
	}
	if rest != "" {
		d, err := time.ParseDuration(rest)
		if err != nil {
			return 0, badWindow(raw)
		}
		total += d
	}

	if total <= 0 || total > maxWindow {
		return 0, fmt.Errorf(
			"%q is not a valid length of time: try 90m, 6h, 3d or 1d12h", raw)
	}

	return total, nil
}

func badWindow(raw string) error {
	return fmt.Errorf(
		"cannot read %q as a length of time: try 90m, 6h, 3d or 1d12h", raw)
}

// view is the snapshot and analysis a request is answered from.
func (s *Server) view(r *http.Request) (*snapshot, *derived, time.Duration) {
	snap := s.current()
	window, _ := parseWindow(r.URL.Query().Get("since"))

	return snap, snap.view(window), window
}

// checkWindow answers an unreadable window once with a 400, rather than
// leaving every handler to fall back to the whole capture and say nothing.
func checkWindow(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		if _, err := parseWindow(r.URL.Query().Get("since")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// parseSlice reads the RFC 3339 from/to of a chart column.
func parseSlice(r *http.Request) (from, to time.Time, err error) {
	read := func(name string) (time.Time, error) {
		raw := r.URL.Query().Get(name)
		if raw == "" {
			return time.Time{}, nil
		}
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("cannot read %s=%q as a time", name, raw)
		}
		return t, nil
	}

	if from, err = read("from"); err != nil {
		return
	}
	to, err = read("to")

	return
}

// within reports whether an event falls in a half open slice.
func within(at, from, to time.Time) bool {
	if !from.IsZero() && at.Before(from) {
		return false
	}
	if !to.IsZero() && !at.Before(to) {
		return false
	}

	return true
}
