package processing

import (
	"math"
	"testing"
	"time"

	"github.com/drduh/mess/internal/event"
)

func TestCadenceSeparatesRhythms(t *testing.T) {
	base := time.Date(2026, 9, 8, 9, 0, 0, 0, time.UTC)
	var events []event.Event
	add := func(at time.Time, path string, cmd ...string) {
		events = append(events, event.Event{Time: at, Path: path, Cmd: cmd})
	}

	// A timed daemon: every 60 seconds with jitter.
	for i := 0; i < 60; i++ {
		add(base.Add(time.Duration(i)*60*time.Second+time.Duration(i%3)*time.Second),
			"/usr/libexec/tickd", "/usr/bin/true")
	}

	// A person: three bursts of quick runs, hours apart.
	for burst := 0; burst < 3; burst++ {
		for i := 0; i < 10; i++ {
			add(base.Add(time.Duration(burst)*4*time.Hour+time.Duration(i)*7*time.Second),
				"/bin/zsh", "/usr/bin/git")
		}
	}

	// Too few runs.
	for i := 0; i < 4; i++ {
		add(base.Add(time.Duration(i)*time.Minute), "/usr/bin/rare", "/usr/bin/true")
	}

	byName := map[string]*Cadence{}
	for _, c := range Cadences(events, 50) {
		byName[c.Name] = c
	}

	tick, ok := byName["tickd"]
	if !ok {
		t.Fatal("the timer should be measured")
	}
	if math.Abs(tick.Median-60) > 2 {
		t.Errorf("timer median = %.1fs, want about 60", tick.Median)
	}
	if tick.Regular < 0.5 {
		t.Errorf("timer regularity = %.2f, want it to read as regular", tick.Regular)
	}

	zsh, ok := byName["zsh"]
	if !ok {
		t.Fatal("the person should be measured")
	}
	if zsh.Regular >= tick.Regular {
		t.Errorf("bursty %.2f should be less regular than a timer %.2f",
			zsh.Regular, tick.Regular)
	}
	if math.Abs(zsh.Median-7) > 1 {
		t.Errorf("burst median = %.1fs, want about 7", zsh.Median)
	}

	if _, seen := byName["rare"]; seen {
		t.Errorf("four runs is below the floor of %d and should not be measured", CadenceFloor)
	}

	total := 0
	for _, n := range tick.Buckets {
		total += n
	}
	if total != tick.Count-1 {
		t.Errorf("timer buckets hold %d gaps, want %d", total, tick.Count-1)
	}
}
