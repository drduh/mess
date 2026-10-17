// Binary endpoints.
package server

import (
	"net/http"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/processing"
)

// binaries is the node list plus the window its activity strips span.
type binaries struct {
	Nodes   []*processing.Node `json:"nodes"`
	Start   time.Time          `json:"start"`
	End     time.Time          `json:"end"`
	Buckets int                `json:"buckets"`
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	_, d, _ := s.view(r)
	writeJSON(w, binaries{
		Nodes:   d.graph.Summaries(),
		Start:   d.timeline.Start,
		End:     d.timeline.End,
		Buckets: strips,
	})
}

// detail is one binary with its neighbours, activity and samples.
type detail struct {
	Node     *processing.Node   `json:"node"`
	Parents  []processing.Count `json:"parents"`
	Children []processing.Count `json:"children"`
	Activity activity           `json:"activity"`
	Samples  []event.Event      `json:"samples"`
	Signals  []string           `json:"signals"`
}

// activity is a track drawn against the whole window.
type activity struct {
	Start   time.Time        `json:"start"`
	End     time.Time        `json:"end"`
	Buckets int              `json:"buckets"`
	Track   processing.Track `json:"track"`
}

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	_, d, _ := s.view(r)
	name := r.URL.Query().Get("name")
	node := d.graph.Nodes[name]
	if node == nil {
		http.Error(w, "no binary named "+name+" in this capture", http.StatusNotFound)
		return
	}

	matches := func(e event.Event) bool {
		return classify.Command(e.Path) == name || classify.Command(e.Image()) == name
	}

	writeJSON(w, detail{
		Node:     node,
		Parents:  d.graph.ParentsOf(name, 12),
		Children: d.graph.ChildrenOf(name, 12),
		Activity: activity{
			Start:   d.timeline.Start,
			End:     d.timeline.End,
			Buckets: d.timeline.Buckets,
			Track: processing.TrackOf(d.events, name,
				d.timeline.Start, d.timeline.End, d.timeline.Buckets, matches),
		},
		Samples: samples(d, matches, 15),
		Signals: d.report.NamedIn(name),
	})
}

func (s *Server) handleOrigins(w http.ResponseWriter, r *http.Request) {
	_, d, _ := s.view(r)
	writeJSON(w, d.graph.Origins)
}

// handleLabels serves the static classification tables.
func (s *Server) handleLabels(w http.ResponseWriter, r *http.Request) {
	roles, cats := classify.Labels()
	writeJSON(w, map[string]any{
		"roles":      roles,
		"categories": cats,
		"vocabulary": classify.Vocabulary,
		"system":     classify.SystemPrefixes(),
		"bits":       classify.BitTables(),
		"bundles":    classify.BundleWords(),
		"notes":      classify.TagNotes(),
	})
}

// samples returns the newest events matching keep.
func samples(d *derived, keep func(event.Event) bool, limit int) []event.Event {
	out := make([]event.Event, 0, limit)
	for _, i := range d.newest {
		if len(out) == limit {
			break
		}
		if keep(d.events[i]) {
			out = append(out, d.events[i])
		}
	}

	return out
}
