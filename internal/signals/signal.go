// Package signals turns events into alerts and notices.
package signals

import (
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
)

type Tier int

const (
	Alert Tier = iota
	Notice
	Context
)

func (t Tier) String() string {
	switch t {
	case Alert:
		return "alert"
	case Notice:
		return "notice"
	}

	return "context"
}

type Row struct {
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	N       int       `json:"n"`
	Measure int       `json:"measure,omitempty"`
	Key     string    `json:"key"`
	Find    string    `json:"find"`
	Who     []string  `json:"who"`
	Marks   []string  `json:"marks"`
}

type Signal struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Tier     string    `json:"tier"`
	Scope    string    `json:"scope"`
	Summary  string    `json:"summary"`
	Because  string    `json:"because"`
	Join     string    `json:"join,omitempty"`
	Count    int       `json:"count"`
	Distinct int       `json:"distinct"`
	Blind    int       `json:"blind,omitempty"`
	Lost     int       `json:"lost,omitempty"`
	Counts   []int     `json:"counts"`
	Rows     []Row     `json:"rows"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Tune     *Tunable  `json:"tune,omitempty"`
}

type Seen struct {
	*event.Event
	concerns     []string
	concernsDone bool
	cache        *classify.Cache
}

func (s *Seen) Concerns() []string {
	if !s.concernsDone {
		s.concerns = s.cache.Concerns(s.Cmd)
		s.concernsDone = true
	}
	return s.concerns
}

func (s *Seen) CallerCategory() string {
	return s.cache.Category(classify.Command(s.Path), s.Path, s.Sign)
}

func (s *Seen) Template() string {
	return s.cache.Template(s.Cmd)
}
