package rules

import (
	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
	"github.com/drduh/mess/internal/signals"
)

const (
	shapeFloor  = 8
	rareCeiling = 2
)

var captureRules = []signals.Rule{
	{
		ID:      "once",
		Title:   "Seen once",
		Tier:    signals.Context,
		Scope:   "binary",
		Cap:     60,
		Summary: "Images launched exactly once in this window.",
		Because: "Most capture variety is here.",
		Walk:    once,
	},
	{
		ID:      "once_third",
		Title:   "Seen once from a non-Apple caller",
		Tier:    signals.Notice,
		Scope:   "binary",
		Cap:     60,
		Summary: "Images launched exactly once in this window by something other than a platform binary.",
		Because: "First-time runs, one-off tools.",
		Walk:    onceThird,
	},
	{
		ID:      "job_rare_shape",
		Title:   "A job ran in an unusual shape",
		Tier:    signals.Notice,
		Scope:   "command",
		Summary: "A program launchd starts for a job ran numerous times with one set of arguments in this window and once or twice with another.",
		Because: "An update changes job arguments, or one program serving two jobs.",
		Walk:    jobRareShape,
	},
	{
		ID:      "dropped",
		Title:   "Events dropped by eslogger",
		Tier:    signals.Context,
		Scope:   "file",
		Summary: "Gaps in the sequence numbers: events the kernel produced that never reached the log.",
		Because: "eslogger may drop events under load.",
		Walk:    dropped,
	},
}

// onceThird is the walk for once_third.
func onceThird(c pids.Capture, emit func(event.Event, string, int)) {
	count := map[string]int{}

	for i := range c.Events {
		e := &c.Events[i]
		count[e.Image()]++
	}

	for i := range c.Events {
		e := &c.Events[i]
		if count[e.Image()] == 1 && !e.Sys {
			emit(*e, e.Image(), 1)
		}
	}
}

// once is the walk for once.
func once(c pids.Capture, emit func(event.Event, string, int)) {
	count := map[string]int{}

	for i := range c.Events {
		e := &c.Events[i]
		count[e.Image()]++
	}

	for i := range c.Events {
		e := &c.Events[i]
		if count[e.Image()] == 1 {
			emit(*e, e.Image(), 1)
		}
	}
}

// dropped is the walk for dropped.
func dropped(c pids.Capture, emit func(event.Event, string, int)) {
	event.SeqWalk(c.Events,
		func(prev, cur event.Event, lost int) {
			name := cur.File
			if name == "" {
				name = "(unnamed file)"
			}

			emit(cur, name, lost)
		}, nil)
}

// jobRareShape is the walk for job_rare_shape.
func jobRareShape(c pids.Capture, emit func(event.Event, string, int)) {
	byJob := map[string]map[string][]int{} // image → template → events

	for i := range c.Events {
		e := &c.Events[i]
		if !jobLaunch(e) {
			continue
		}

		shapes := byJob[e.Image()]
		if shapes == nil {
			shapes = map[string][]int{}
			byJob[e.Image()] = shapes
		}

		t := c.Cache.Template(e.Cmd)
		shapes[t] = append(shapes[t], i)
	}

	for _, shapes := range byJob {
		usual, most, all := "", 0, 0
		for t, evs := range shapes {
			all += len(evs)
			if len(evs) > most || (len(evs) == most && t < usual) {
				usual, most = t, len(evs)
			}
		}

		if most < shapeFloor || all == most || all-most > rareCeiling {
			continue
		}

		for t, evs := range shapes {
			if t == usual {
				continue
			}

			for _, i := range evs {
				emit(c.Events[i], line(&c.Events[i]), 1)
			}
		}
	}
}

// jobLaunch is a non-Apple program launchd started for a job.
func jobLaunch(e *event.Event) bool {
	t := &e.Target
	if !t.Known() || t.Sys || len(e.Cmd) == 0 {
		return false
	}

	switch classify.Command(e.Path) {
	case "launchd", "xpcproxy":
		return true
	}

	return false
}
