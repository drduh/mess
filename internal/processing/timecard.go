package processing

import (
	"time"

	"github.com/drduh/mess/internal/event"
)

func ranAs(e event.Event, uid uint32) bool {
	if e.UID == uid {
		return true
	}

	return e.AUID != nil && *e.AUID == uid && *e.AUID != event.NoAUID
}

type Timecard struct {
	App    [7][24]int `json:"app"`
	Person [7][24]int `json:"person"`
	System [7][24]int `json:"system"`

	Totals map[string]int `json:"totals"`
	Offset int            `json:"offset"`
	Days   []string       `json:"days"`
}

// BuildTimecard folds events by weekday and hour.
func BuildTimecard(events []event.Event, offset int, who *uint32) Timecard {
	t := Timecard{
		Offset: offset,
		Days:   []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
		Totals: map[string]int{"person": 0, "app": 0, "system": 0},
	}

	zone := time.FixedZone("reader", offset*60)
	for _, e := range events {
		if who != nil && !ranAs(e, *who) {
			continue
		}

		local := e.Time.In(zone)
		day := (int(local.Weekday()) + 6) % 7 // start on Monday
		hour := local.Hour()

		switch Actor(e) {
		case "app":
			t.App[day][hour]++
			t.Totals["app"]++
		case "person":
			t.Person[day][hour]++
			t.Totals["person"]++
		default:
			t.System[day][hour]++
			t.Totals["system"]++
		}
	}

	return t
}
