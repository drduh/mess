package pids

import (
	"sort"
	"strconv"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
)

type Process struct {
	ID     string    `json:"id"` // pid (pid#n for reused pids)
	PID    int       `json:"pid"`
	PPID   int       `json:"ppid"`
	SID    int       `json:"sid,omitempty"`
	UID    uint32    `json:"uid"` // as of the last exec
	TTY    string    `json:"tty,omitempty"`
	Name   string    `json:"name"` // the last image, as command name
	Path   string    `json:"path"` // the last image
	Images []string  `json:"images"`
	Caller string    `json:"caller,omitempty"`
	Execs  int       `json:"execs"`
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
}

type Index struct {
	All []*Process
	by  map[int][]*Process
}

// NewIndex builds the index over a slice of processes.
func NewIndex(procs []Process) Index {
	idx := Index{All: make([]*Process, len(procs)), by: map[int][]*Process{}}
	for i := range procs {
		idx.All[i] = &procs[i]
		idx.by[procs[i].PID] = append(idx.by[procs[i].PID], idx.All[i])
	}
	for _, ps := range idx.by {
		sort.Slice(ps, func(i, j int) bool { return ps[i].First.Before(ps[j].First) })
	}
	return idx
}

// At returns the process holding a pid at a moment in time.
func (idx Index) At(pid int, at time.Time, not *Process, fits ...func(*Process) bool) *Process {
	var covering, started *Process
	for _, cand := range idx.by[pid] {
		if cand == not || cand.First.After(at) {
			continue
		}
		if len(fits) > 0 && fits[0] != nil && !fits[0](cand) {
			continue
		}
		if !cand.Last.Before(at) {
			covering = cand
		}
		started = cand // the latest to start
	}
	if covering != nil {
		return covering
	}
	return started
}

func reused(p *Process, e *event.Event) bool {
	if p.Path == "" || e.Path == "" {
		return false
	}
	return e.Path != p.Path
}

func CouldHaveForked(parent, child *Process) bool {
	if child.Caller == "" {
		return true
	}
	for _, img := range parent.Images {
		if img == child.Caller {
			return true
		}
	}
	return false
}

func Processes(events []event.Event) []Process {
	type key struct{ pid, ppid int }
	byKey := map[key]*Process{}
	seen := map[int]int{}
	var out []*Process

	for i := range events {
		e := &events[i]
		k := key{e.PID, e.PPID}
		p := byKey[k]
		if p != nil && reused(p, e) {
			p = nil
		}
		if p == nil {
			seen[e.PID]++
			p = &Process{
				PID:    e.PID,
				PPID:   e.PPID,
				SID:    e.SID,
				First:  e.Time,
				Last:   e.Time,
				Caller: e.Path,
			}
			p.ID = strconv.Itoa(e.PID)
			if seen[e.PID] > 1 {
				p.ID += "#" + strconv.Itoa(seen[e.PID])
			}
			byKey[k] = p
			out = append(out, p)
		}
		img := e.Image()

		if len(p.Images) == 0 || p.Images[len(p.Images)-1] != img {
			p.Images = append(p.Images, img)
			p.Path = img
			p.Name = classify.Command(img)
		}

		if e.Target.Known() {
			p.UID = e.Target.UID
		} else {
			p.UID = e.UID
		}

		if e.TTY != "" {
			p.TTY = e.TTY
		}
		p.Execs++

		if e.Time.Before(p.First) {
			p.First = e.Time
		}

		if e.Time.After(p.Last) {
			p.Last = e.Time
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].First.Before(out[j].First)
	})

	list := make([]Process, len(out))
	for i, p := range out {
		list[i] = *p
	}

	return list
}

type Capture struct {
	Cache  *classify.Cache
	Events []event.Event
	Index  Index
}

// Over folds events into processes and indexes them.
func Over(events []event.Event) Capture {
	return Capture{
		Events: events,
		Index:  NewIndex(Processes(events)),
		Cache:  classify.NewCache(),
	}
}
