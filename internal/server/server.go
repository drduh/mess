// Package server provides the HTTP application.
package server

import (
	"embed"
	"io/fs"
	"sync"
	"time"

	"github.com/drduh/mess/internal/event"
)

//go:embed static/*.html
var assets embed.FS

type Server struct {
	onRead func(name string)
	fsys   fs.FS

	pattern string
	errLog  string

	mu sync.RWMutex
}

type snapshot struct {
	loaded event.Loaded
	last   time.Time // newest event
	read   time.Time

	mu    sync.Mutex
	views map[time.Duration]*pending
}

type pending struct {
	mu   sync.Mutex
	done bool
}

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

	return nil
}
