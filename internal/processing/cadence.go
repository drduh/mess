package processing

import (
	"math"
	"sort"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/tally"
)

// Cadence is how long a binary waited between runs.
type Cadence struct {
	Name     string `json:"name"`
	Count    int    `json:"count"`
	Kind     string `json:"kind"`
	Category string `json:"category"`
	Role     string `json:"role"`

	Median  float64 `json:"median"`
	Regular float64 `json:"regular"`

	Buckets []int     `json:"buckets"`
	Peak    int       `json:"peak"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

// GapEdges are the upper bounds of each gap bucket in seconds.
var GapEdges = []float64{1, 2, 5, 10, 30, 60, 120, 300, 900, 3600, 21600, math.Inf(1)}

// GapLabels name those bounds for the axis.
var GapLabels = []string{"1s", "2s", "5s", "10s", "30s", "1m", "2m", "5m", "15m", "1h", "6h", "+"}

// CadenceFloor is the fewest runs worth measuring.
const CadenceFloor = 8

// Cadences measures every binary that ran often enough, busiest first.
func Cadences(events []event.Event, top int) []*Cadence {
	order := make([]int, len(events))
	for i := range order {
		order[i] = i
	}

	sort.SliceStable(order, func(a, b int) bool {
		return events[order[a]].Time.Before(events[order[b]].Time)
	})

	type run struct {
		last time.Time
		gaps []float64
		c    *Cadence
	}
	runs := map[string]*run{}

	note := func(name, path string, at time.Time) {
		if name == "" {
			return
		}

		r := runs[name]
		if r == nil {
			runs[name] = &run{last: at, c: &Cadence{
				Name:     name,
				Kind:     classify.Kind(name, path),
				Category: classify.Category(name, path, ""),
				Role:     classify.Role(name),
				Buckets:  make([]int, len(GapEdges)),
				First:    at,
				Last:     at,
			}}
			runs[name].c.Count = 1
			return
		}
		r.c.Count++
		r.c.Last = at

		gap := at.Sub(r.last).Seconds()
		r.last = at
		if gap < 0 {
			return
		}

		r.gaps = append(r.gaps, gap)
		for i, edge := range GapEdges {
			if gap < edge {
				r.c.Buckets[i]++
				break
			}
		}
	}

	for _, i := range order {
		e := events[i]
		note(classify.Command(e.Path), e.Path, e.Time)
		img := e.Image()
		if name := classify.Command(img); name != classify.Command(e.Path) {
			note(name, img, e.Time)
		}
	}

	ranked := make([]Count, 0, len(runs))
	for name, r := range runs {
		if r.c.Count < CadenceFloor {
			continue
		}

		r.c.Median, r.c.Regular = shape(r.gaps)
		for _, n := range r.c.Buckets {
			if n > r.c.Peak {
				r.c.Peak = n
			}
		}

		ranked = append(ranked, Count{Key: name, N: r.c.Count})
	}

	if top <= 0 {
		top = len(ranked)
	}

	out := make([]*Cadence, 0, len(ranked))
	for _, c := range tally.SortTop(ranked, top) {
		out = append(out, runs[c.Key].c)
	}

	return out
}

// shape returns the median gap and how tightly the gaps cluster around it.
func shape(gaps []float64) (median, regular float64) {
	if len(gaps) == 0 {
		return 0, 0
	}

	sorted := append([]float64(nil), gaps...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	median = sorted[mid]

	if len(sorted)%2 == 0 {
		median = (sorted[mid-1] + sorted[mid]) / 2
	}

	if median <= 0 {
		return median, 0
	}

	band := median * 0.1
	near := 0

	for _, g := range gaps {
		if math.Abs(g-median) <= band {
			near++
		}
	}

	return median, float64(near) / float64(len(gaps))
}
