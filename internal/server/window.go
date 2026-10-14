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
