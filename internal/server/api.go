// JSON API
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// capture describes what was read, for the header.
type capture struct {
	Events  int       `json:"events"` // inside the window
	Total   int       `json:"total"`  // in the whole capture
	Files   []string  `json:"files"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Seconds float64   `json:"seconds"`
	Read    time.Time `json:"read"`
}

func describe(snap *snapshot, d *derived) capture {
	return capture{
		Events:  len(d.events),
		Total:   len(snap.loaded.Events),
		Files:   snap.loaded.Files,
		First:   d.report.First,
		Last:    d.report.Last,
		Seconds: d.report.Last.Sub(d.report.First).Seconds(),
		Read:    snap.read,
	}
}

// view is the snapshot and analysis a request is answered from.
func (s *Server) view(r *http.Request) (*snapshot, *derived) {
	snap := s.current()

	return snap, snap.view(0)
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	snap, d := s.view(r)
	writeJSON(w, describe(snap, d))
}

// handleReload re-reads the directory and reports what is now loaded.
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if err := s.Reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	snap, d := s.view(r)
	writeJSON(w, describe(snap, d))
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	_, d := s.view(r)
	writeJSON(w, d.report)
}

// writeJSON encodes into a buffer before writing a byte: encoding
// straight to the ResponseWriter commits a 200 and part of a body
// before it can fail. Either the whole document is sent or an error is.
func writeJSON(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	_, _ = w.Write(buf.Bytes())
}
