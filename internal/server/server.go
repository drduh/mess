// Package server provides the HTTP application.
package server

import (
	"embed"
	"io/fs"
	"sync"
	"time"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
	"github.com/drduh/mess/internal/processing"
)

//go:embed static/*.html
var assets embed.FS

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

	return d
}

// derived is the analysis of one window of the capture.
type derived struct {
	events []event.Event
	report processing.Report
	graph  *processing.Graph
}

// view returns the analysis for the window, building it on first use.
func (snap *snapshot) view(window time.Duration) *derived {
	snap.mu.Lock()
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
	if window > 0 {
		cutoff := snap.last.Add(-window)
		if at, ok := windowStarts(events, cutoff); ok {
			events = events[at:len(events):len(events)]
		} else {
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
