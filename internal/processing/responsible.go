package processing

import (
	"sort"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/tally"
)

// Requester is a process responsible for launches, with a count.
type Requester struct {
	Name  string `json:"name"`
	PID   int    `json:"pid"`
	N     int    `json:"n"`
	Self  bool   `json:"self"`
	Named bool   `json:"named"`
}

// ranAt indexes each pid execs in time order.
func ranAt(events []event.Event) map[int][]event.Event {
	by := map[int][]event.Event{}

	for _, e := range events {
		by[e.PID] = append(by[e.PID], e)
	}

	for _, list := range by {
		sort.SliceStable(list, func(i, j int) bool { return list[i].Time.Before(list[j].Time) })
	}

	return by
}

// imageOf is a pid image at a moment.
func imageOf(by map[int][]event.Event, pid int, at time.Time) (string, bool) {
	list := by[pid]
	i := sort.Search(len(list), func(i int) bool { return list[i].Time.After(at) })
	if i == 0 {
		return "", false
	}

	return classify.Command(list[i-1].Image()), true
}

// Responsible reports launches of the named binary.
func Responsible(events []event.Event, name string, top int) (out []Requester, self, unnamed int) {
	by := ranAt(events)
	who := tally.Counter{}
	heldPID := map[string]int{}

	for _, e := range events {
		if !e.Target.Known() || classify.Command(e.Target.Path) != name {
			continue
		}

		if e.RPID == 0 || e.RPID == e.PID {
			self++
			continue
		}

		img, ok := imageOf(by, e.RPID, e.Time)
		if !ok {
			unnamed++
			continue
		}

		who.Add(img)
		heldPID[img] = e.RPID
	}

	for _, c := range who.Top(top) {
		out = append(out, Requester{
			Name:  c.Key,
			PID:   heldPID[c.Key],
			N:     c.N,
			Named: true},
		)
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].N > out[j].N })

	return out, self, unnamed
}
