// Chart endpoints.
package server

import (
	"net/http"
	"strings"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/processing"
)

// handleTimeline serves the timeline, narrowed by ?who= and ?tags=.
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	_, d, _ := s.view(r)
	tags := r.URL.Query().Get("tags")
	who := r.URL.Query().Get("who")
	if tags == "" && who == "" {
		writeJSON(w, d.timeline)
		return
	}

	events := d.events
	if who != "" {
		kept := make([]event.Event, 0, len(events))
		for _, e := range events {
			if processing.Actor(e) == who {
				kept = append(kept, e)
			}
		}
		events = kept
	}

	keep := func(string) bool { return true }
	if tags != "" {
		keep = tagged(d, tags)
	}

	writeJSON(w, processing.BuildTimeline(events, buckets, tracks, keep))
}

// tagged accepts a binary with any of the tags.
func tagged(d *derived, tags string) func(string) bool {
	want := map[string]bool{}
	for _, t := range strings.Split(tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			want[t] = true
		}
	}

	return func(name string) bool {
		n := d.graph.Nodes[name]
		if n == nil {
			return false
		}
		if want[n.Category] || want[n.Role] || want[n.Kind] {
			return true
		}
		for _, o := range n.Origins {
			if want[o] {
				return true
			}
		}

		return false
	}
}
