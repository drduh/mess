// Event stream endpoint.
package server

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/processing"
)

// page is a slice of the matches plus their total and histogram.
type page struct {
	Events []event.Event `json:"events"`
	Offset int           `json:"offset"`
	Total  int           `json:"total"`
	Counts []int         `json:"counts"`
	Peak   int           `json:"peak"`

	// A slice of the window, picked from a chart column.
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Ranged  int       `json:"ranged"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Buckets int       `json:"buckets"`
}

// handleEvents pages through the events matching ?q=, newest first.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	_, d, _ := s.view(r)
	offset := intParam(r, "offset", 0, 0, len(d.newest))
	limit := intParam(r, "limit", 100, 1, 1000)
	q := parseQuery(r.URL.Query().Get("q"))
	asc := r.URL.Query().Get("dir") == "asc"
	key := eventSortKey(r.URL.Query().Get("sort"))
	from, to, err := parseSlice(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	out := page{
		Events:  make([]event.Event, 0, limit),
		Offset:  offset,
		From:    from,
		To:      to,
		Counts:  make([]int, strips),
		Start:   d.timeline.Start,
		End:     d.timeline.End,
		Buckets: strips,
	}

	span := out.End.Sub(out.Start)
	if span <= 0 {
		span = time.Second
	}
	at := processing.Bucketer(out.Start, span, strips)

	// Count every match; page as we go or gather to sort.
	var matched []int
	seen := 0
	for n := range d.newest {
		i := d.newest[n]
		if key == nil && asc {
			i = d.newest[len(d.newest)-1-n]
		}
		e := d.events[i]
		if !q.match(e) {
			continue
		}
		out.Total++
		out.Counts[at(e.Time)]++
		if !within(e.Time, from, to) {
			continue
		}
		out.Ranged++
		if key != nil {
			matched = append(matched, i)
			continue
		}
		if seen >= offset && len(out.Events) < limit {
			out.Events = append(out.Events, e)
		}
		seen++
	}

	if key != nil {
		// Stable, so ties keep stream order and paging is consistent.
		sort.SliceStable(matched, func(a, b int) bool {
			ka, kb := key(d.events[matched[a]]), key(d.events[matched[b]])
			if ka == kb {
				return false
			}
			if asc {
				return ka < kb
			}
			return ka > kb
		})
		for n := offset; n < len(matched) && len(out.Events) < limit; n++ {
			out.Events = append(out.Events, d.events[matched[n]])
		}
	}

	for _, c := range out.Counts {
		if c > out.Peak {
			out.Peak = c
		}
	}

	writeJSON(w, out)
}

// eventSortKey is a column's sort key, or nil for time order.
func eventSortKey(col string) func(event.Event) string {
	pad := func(n int64) string { return fmt.Sprintf("%016d", n) }
	switch col {
	case "user":
		return func(e event.Event) string { return pad(int64(e.UID)) }
	case "caller":
		return func(e event.Event) string { return strings.ToLower(classify.Command(e.Path)) }
	case "started":
		return func(e event.Event) string { return strings.ToLower(classify.Command(e.Image())) }
	case "signing":
		return func(e event.Event) string {
			if e.Target.Known() {
				return strings.ToLower(e.Target.Team + " " + e.Target.Sign)
			}
			return strings.ToLower(e.Team + " " + e.Sign)
		}
	case "argv":
		return func(e event.Event) string { return strings.ToLower(strings.Join(e.Cmd, " ")) }
	case "pid":
		return func(e event.Event) string { return pad(int64(e.PID)) }
	case "ppid":
		return func(e event.Event) string { return pad(int64(e.PPID)) }
	case "session":
		return func(e event.Event) string { return pad(int64(e.SID)) }
	case "tty":
		return func(e event.Event) string { return e.TTY }
	case "cwd":
		return func(e event.Event) string { return strings.ToLower(e.CWD) }
	case "arch":
		return func(e event.Event) string { return pad(int64(e.CPU)) }
	case "seq":
		return func(e event.Event) string { return pad(e.Seq) }
	}

	return nil
}

// intParam reads a bounded integer, or def if unreadable.
func intParam(r *http.Request, name string, def, lo, hi int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}

	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}

	return min(hi, max(lo, n))
}
