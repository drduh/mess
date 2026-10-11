package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseWindow(t *testing.T) {
	for raw, want := range map[string]time.Duration{
		"15m":     15 * time.Minute,
		" 6h ":    6 * time.Hour,
		"3d":      72 * time.Hour,
		"1d12h":   36 * time.Hour,
		"36525d":  time.Duration(36525) * 24 * time.Hour,
		"":        0,
		"all":     0,
		"1h30m5s": time.Hour + 30*time.Minute + 5*time.Second,
	} {
		got, err := parseWindow(raw)
		if err != nil || got != want {
			t.Errorf("parseWindow(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}

	for _, raw := range []string{
		"106752d", "213504d", "1000000d", "9223372036854775807d",
		"0", "0h", "-1h", "3 days", "d", "1dd", "soon"} {
		if got, err := parseWindow(raw); err == nil {
			t.Errorf("parseWindow(%q) = %v, want an error", raw, got)
		}
	}
}

// The window selects the tail of the capture, and the header says
// which window the counts are inside.
func TestSinceSelectsAWindow(t *testing.T) {
	s := &Server{fsys: logs(base, 10, "mess-v1-a.log"), pattern: "mess-v1-*.log"}
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	h := s.Handler("")

	get := func(path string) (int, capture) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		var got capture
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		return rec.Code, got
	}

	if code, got := get("/api/capture?since=3s"); code != 200 || got.Events != 4 || got.Total != 10 || got.Window != "3s" {
		t.Errorf("since=3s: %d, %d of %d in %q; want 200, 4 of 10 in \"3s\"", code, got.Events, got.Total, got.Window)
	}

	if code, got := get("/api/capture?since=all"); code != 200 || got.Events != 10 {
		t.Errorf("since=all: %d, %d events; want 200 and 10", code, got.Events)
	}

	if code, got := get("/api/capture?since=1d"); code != 200 || got.Events != 10 {
		t.Errorf("since=1d: %d, %d events; want 200 and all 10", code, got.Events)
	}
}

// An unreadable window is a 400 from the API, and nothing from the
// page, which a stale bookmark must still be able to load.
func TestCheckWindowRejectsOnce(t *testing.T) {
	reached := false
	h := checkWindow(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/report?since=soon", nil))
	if rec.Code != http.StatusBadRequest || reached {
		t.Errorf("api with a bad window: %d, reached %v; want 400 and not reached", rec.Code, reached)
	}

	reached = false
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/?since=soon", nil))
	if !reached {
		t.Error("the page was refused for its query string")
	}
}
