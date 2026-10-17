// Package server provides the HTTP application.
package server

import (
	"embed"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
	"github.com/drduh/mess/internal/processing"
)

//go:embed static/*.html
var assets embed.FS

const (
	// Windows whose analysis is kept before the cache is started over.
	windowCache = 12

	// Bytes the cached windows may hold between them.
	windowBudget = 256 << 20

	// What one event.Event occupies, pinned by a test.
	eventBytes = 408

	// Fixed and per-event bytes an analysis retains.
	analysisFixed    = 1_200_000
	analysisPerEvent = 12
)

// analysisBytes estimates what one window's analysis holds.
func analysisBytes(events int, copied bool) int64 {
	n := int64(analysisFixed) + int64(events)*analysisPerEvent
	if copied {
		n += int64(events) * eventBytes
	}

	return n
}

type Server struct {
	onRead func(name string)
	fsys   fs.FS

	pattern string
	errLog  string

	mu   sync.RWMutex
	snap *snapshot
}

// snapshot is one read of the log directory.
type snapshot struct {
	loaded event.Loaded
	last   time.Time // newest event
	read   time.Time

	mu    sync.Mutex
	views map[time.Duration]*pending
}

// pending is one window's analysis.
type pending struct {
	mu   sync.Mutex
	done bool
	d    *derived

	// Estimated bytes held, zero while building.
	size atomic.Int64
}

// get builds the analysis once and answers every caller with it.
func (p *pending) get(build func() *derived, forget func()) *derived {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done {
		return p.d
	}

	made := false
	defer func() {
		if !made {
			forget()
		}
	}()

	d := build()
	p.d, p.done, made = d, true, true
	if d != nil {
		p.size.Store(d.held)
	}

	return d
}

// derived is the analysis of one window of the capture.
type derived struct {
	held   int64 // estimated bytes, for the cache's bound
	events []event.Event
	report processing.Report
	graph  *processing.Graph
}

// view returns the analysis for the window, building it on first use.
func (snap *snapshot) view(window time.Duration) *derived {
	snap.mu.Lock()
	// Bound the cache, keeping the whole capture.
	if len(snap.views) >= windowCache || snap.held() >= windowBudget {
		whole, ok := snap.views[0]
		snap.views = map[time.Duration]*pending{}
		if ok {
			snap.views[0] = whole
		}
	}
	p, ok := snap.views[window]
	if !ok {
		p = &pending{}
		snap.views[window] = p
	}
	snap.mu.Unlock()

	return p.get(
		func() *derived { return snap.build(window) },
		func() { snap.forget(window, p) })
}

// held sums the finished analyses; call with snap.mu held.
func (snap *snapshot) held() int64 {
	var n int64
	for _, p := range snap.views {
		n += p.size.Load()
	}

	return n
}

// forget drops one window's entry.
func (snap *snapshot) forget(window time.Duration, p *pending) {
	snap.mu.Lock()
	if snap.views[window] == p {
		delete(snap.views, window)
	}
	snap.mu.Unlock()
}

// windowStarts is the index where the window begins, when the window
// is the tail of the capture.
func windowStarts(events []event.Event, cutoff time.Time) (int, bool) {
	at := -1
	for i := range events {
		if events[i].Time.Before(cutoff) {
			if at >= 0 {
				return 0, false
			}
			continue
		}
		if at < 0 {
			at = i
		}
	}

	if at < 0 {
		at = len(events)
	}

	return at, true
}

// build is the whole analysis of one window.
func (snap *snapshot) build(window time.Duration) *derived {
	events := snap.loaded.Events
	copied := false
	if window > 0 {
		cutoff := snap.last.Add(-window)
		if at, ok := windowStarts(events, cutoff); ok {
			events = events[at:len(events):len(events)]
		} else {
			copied = true
			kept := make([]event.Event, 0, len(events)/4)
			for i := range events {
				if !events[i].Time.Before(cutoff) {
					kept = append(kept, events[i])
				}
			}
			events = kept
		}
	}

	return &derived{
		held:   analysisBytes(len(events), copied),
		events: events,
		report: processing.Analyze(pids.Over(events)),
		graph:  processing.BuildGraph(events),
	}
}

// Reload re-reads the log files and replaces the snapshot.
func (s *Server) Reload() error {
	loaded, err := event.LoadEach(s.fsys, s.pattern, s.onRead)
	if err != nil {
		return err
	}

	next := &snapshot{
		loaded: loaded,
		read:   time.Now(),
		views:  map[time.Duration]*pending{},
	}

	for _, e := range loaded.Events {
		if e.Time.After(next.last) {
			next.last = e.Time
		}
	}

	next.view(0) // the whole capture, so the first page is ready

	s.mu.Lock()
	s.snap = next
	s.mu.Unlock()

	return nil
}

// current returns the snapshot to answer a request from, nil before
// the first read lands.
func (s *Server) current() *snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.snap
}
