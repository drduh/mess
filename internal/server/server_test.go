package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/drduh/mess/internal/event"
)

// logs is a small capture in memory: n events a second apart, from the
// base time, in one file per file name given.
func logs(base time.Time, n int, files ...string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for fi, name := range files {
		var b strings.Builder
		for i := range n {
			at := base.Add(time.Duration(fi*n+i) * time.Second)
			fmt.Fprintf(&b, `{"time":%q,"pid":%d,"ppid":1,"uid":501,"path":"/bin/zsh","sys":true,"cmd":["ls"]}`+"\n",
				at.Format(time.RFC3339Nano), 100+fi*n+i)
		}
		fsys[name] = &fstest.MapFile{Data: []byte(b.String())}
	}

	return fsys
}

var base = time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// Port opens before the capture is read.
func TestReadyHoldsTheAPIBackButNotThePage(t *testing.T) {
	s := &Server{fsys: logs(base, 2, "exec-a.log"), pattern: "*.log"}
	reached := false
	h := s.ready(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))

	for _, path := range []string{"/api/capture", "/api/report"} {
		reached = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s before the read = %d, want 503", path, rec.Code)
		}

		if reached {
			t.Errorf("%s reached the handler with no snapshot", path)
		}

		if rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s: no Retry-After", path)
		}
	}

	reached = false
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if !reached {
		t.Error("the page was held back too; there would be nothing to wait in")
	}

	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	reached = false
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/capture", nil))

	if !reached || rec.Code == http.StatusServiceUnavailable {
		t.Error("the API is still held back after the read")
	}
}

func TestCaptureDescribesWhatWasRead(t *testing.T) {
	s := &Server{fsys: logs(base, 3, "exec-a.log", "exec-b.log"), pattern: "exec-*.log"}
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	rec := httptest.NewRecorder()
	s.Handler("").ServeHTTP(rec, httptest.NewRequest("GET", "/api/capture", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}

	var got capture
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Events != 6 || got.Total != 6 {
		t.Errorf("events = %d of %d, want 6 of 6", got.Events, got.Total)
	}

	if len(got.Files) != 2 {
		t.Errorf("files = %v, want both", got.Files)
	}

	if !got.First.Equal(base) || !got.Last.Equal(base.Add(5*time.Second)) || got.Seconds != 5 {
		t.Errorf("span = %v to %v (%vs), want the first and last event", got.First, got.Last, got.Seconds)
	}

	if got.Read.IsZero() {
		t.Error("read time is zero")
	}
}

func TestReportCountsTheCapture(t *testing.T) {
	s := &Server{fsys: logs(base, 4, "exec-a.log"), pattern: "exec-*.log"}
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	rec := httptest.NewRecorder()
	s.Handler("").ServeHTTP(rec, httptest.NewRequest("GET", "/api/report", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var got struct {
		Total int `json:"total"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Total != 4 {
		t.Errorf("total = %d, want 4", got.Total)
	}
}

// A reload is asked for with POST; the files may have grown since.
func TestReloadReadsAgain(t *testing.T) {
	fsys := logs(base, 2, "exec-a.log")
	s := &Server{fsys: fsys, pattern: "exec-*.log"}
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	h := s.Handler("")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/reload", nil))
	if rec.Code == http.StatusOK {
		t.Errorf("GET /api/reload = %d; a reload must be asked for with POST", rec.Code)
	}

	fsys["exec-b.log"] = logs(base.Add(time.Hour), 3, "x")["x"]
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/reload", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/reload = %d, want 200", rec.Code)
	}

	var got capture
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Total != 5 {
		t.Errorf("total after reload = %d, want 5", got.Total)
	}
}

// The window is the tail of the capture when the files arrive in time
// order, and a copy when they interleave; either way it holds exactly
// the events from the cutoff on.
func TestWindowHoldsTheTail(t *testing.T) {
	ev := func(sec int) event.Event { return event.Event{Time: base.Add(time.Duration(sec) * time.Second)} }
	ordered := []event.Event{ev(0), ev(10), ev(20), ev(30)}
	interleaved := []event.Event{ev(0), ev(30), ev(10), ev(20)}

	for name, events := range map[string][]event.Event{
		"ordered":     ordered,
		"interleaved": interleaved,
	} {
		snap := &snapshot{loaded: event.Loaded{Events: events}, last: ev(30).Time,
			views: map[time.Duration]*pending{}}

		if got := len(snap.view(0).events); got != 4 {
			t.Errorf("%s: whole capture holds %d, want 4", name, got)
		}

		if got := len(snap.view(15 * time.Second).events); got != 2 {
			t.Errorf("%s: last 15s holds %d, want 2", name, got)
		}

		if got := len(snap.view(time.Hour).events); got != 4 {
			t.Errorf("%s: last hour holds %d, want 4", name, got)
		}
	}

	if at, ok := windowStarts(ordered, ev(15).Time); !ok || at != 2 {
		t.Errorf("windowStarts(ordered) = %d, %v; want 2, true", at, ok)
	}

	if _, ok := windowStarts(interleaved, ev(15).Time); ok {
		t.Error("windowStarts(interleaved) said the window was a tail")
	}
}

// A window shares the capture's array; it must not append to it.
func TestWindowCannotGrowIntoTheCapture(t *testing.T) {
	ev := func(sec int) event.Event { return event.Event{Time: base.Add(time.Duration(sec) * time.Second)} }
	events := make([]event.Event, 0, 8) // spare capacity, as a loader's append leaves
	events = append(events, ev(0), ev(10), ev(20))
	snap := &snapshot{loaded: event.Loaded{Events: events}, last: ev(20).Time,
		views: map[time.Duration]*pending{}}

	w := snap.view(5 * time.Second).events
	if len(w) != 1 || cap(w) != 1 {
		t.Errorf("window len %d cap %d, want 1 and 1", len(w), cap(w))
	}
}

// A build that panics leaves the entry unclaimed, so the next request
// builds again instead of dereferencing a nil analysis forever.
func TestAFailedBuildIsRetried(t *testing.T) {
	snap := &snapshot{views: map[time.Duration]*pending{}}
	p := &pending{}
	snap.views[0] = p

	func() {
		defer func() { _ = recover() }()
		p.get(func() *derived { panic("boom") }, func() { snap.forget(0, p) })
	}()
	if snap.views[0] != nil {
		t.Fatal("the failed entry was not forgotten")
	}

	built := 0
	d := snap.view(0)
	if d == nil {
		t.Fatal("nil analysis after a retry")
	}

	for range 3 {
		if snap.view(0) != d {
			built++
		}
	}

	if built != 0 {
		t.Errorf("the analysis was rebuilt %d times", built)
	}
}

func TestPlural(t *testing.T) {
	for _, c := range []struct {
		n    int
		noun string
		want string
	}{
		{1, "file", "1 file"}, {2, "file", "2 files"},
		{1, "binary", "1 binary"}, {0, "binary", "0 binaries"},
	} {
		if got := plural(c.n, c.noun); got != c.want {
			t.Errorf("plural(%d, %q) = %q, want %q", c.n, c.noun, got, c.want)
		}
	}
}
