package signals

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
)

// Tunable is a threshold the reader owns declared by the rule it bounds.
type Tunable struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Unit    string `json:"unit"`
	Keep    string `json:"keep"`
	Note    string `json:"note"`
	Default int    `json:"default"`
	Choices []int  `json:"choices"`
}

type Rule struct {
	Cap     int
	ID      string
	Join    string
	Title   string
	Scope   string
	Summary string
	Because string
	Tier    Tier
	Tune    *Tunable
	Match   func(e *Seen) string
	Walk    func(c pids.Capture, emit func(e event.Event, key string, n int))
	Measure func(e event.Event) int
}

var Scopes = map[string]string{
	"command":  "the command line, templated",
	"path":     "the path of the binary the row is about",
	"binary":   "the binary by name, wherever it ran from",
	"identity": "a signing identity or team",
	"file":     "a log file, for rows about the capture itself",
}

var Joins = map[string]string{
	"job": "the key names a launchd label",
}

var idShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var tuneUnits = map[string]bool{"seconds": true, "count": true}

// Validate is every constraint a rule has to meet.
func (r Rule) Validate() error {
	switch {
	case r.ID == "":
		return errors.New("a rule needs an id")
	case !idShape.MatchString(r.ID):
		return fmt.Errorf(
			"rule id %q: lower-case letters, digits and underscores only", r.ID)
	case r.Title == "":
		return fmt.Errorf(
			"rule %s: needs a title", r.ID)
	case r.Summary == "":
		return fmt.Errorf(
			"rule %s: needs a summary", r.ID)
	case r.Because == "":
		return fmt.Errorf(
			"rule %s: needs a Because, the ordinary explanation", r.ID)
	case r.Tier < Alert || r.Tier > Context:
		return fmt.Errorf(
			"rule %s: tier %d is not alert, notice or context", r.ID, r.Tier)
	case Scopes[r.Scope] == "":
		return fmt.Errorf(
			"rule %s: scope %q is not one of %s", r.ID, r.Scope, scopeWords())
	case (r.Match == nil) == (r.Walk == nil):
		return fmt.Errorf(
			"rule %s: exactly one of Match and Walk", r.ID)
	case r.Tune != nil && r.Measure == nil:
		return fmt.Errorf(
			"rule %s: a threshold with nothing measured to compare it against", r.ID)
	case r.Tune == nil && r.Measure != nil:
		return fmt.Errorf(
			"rule %s: measures a number nothing thresholds", r.ID)
	case r.Cap < 0:
		return fmt.Errorf(
			"rule %s: a negative cap keeps nothing", r.ID)
	case r.Join != "" && Joins[r.Join] == "":
		return fmt.Errorf(
			"rule %s: join %q is not one of %s", r.ID, r.Join, joinWords())
	}
	if r.Tune != nil {
		if err := r.Tune.validate(r.ID); err != nil {
			return err
		}
	}
	return nil
}

func (t Tunable) validate(rule string) error {
	switch {
	case !idShape.MatchString(t.Key):
		return fmt.Errorf(
			"rule %s: threshold key %q: lower letters, digits and underscores only", rule, t.Key)
	case t.Label == "":
		return fmt.Errorf(
			"rule %s: the threshold needs a label", rule)
	case t.Note == "":
		return fmt.Errorf(
			"rule %s: the threshold needs a note saying what moving it does", rule)
	case !tuneUnits[t.Unit]:
		return fmt.Errorf(
			"rule %s: threshold unit %q is not seconds or count", rule, t.Unit)
	case t.Keep != "below" && t.Keep != "above":
		return fmt.Errorf(
			"rule %s: threshold keeps %q, not below or above", rule, t.Keep)
	case len(t.Choices) == 0:
		return fmt.Errorf(
			"rule %s: the threshold offers no choices", rule)
	}

	for _, c := range t.Choices {
		if c == t.Default {
			return nil
		}
	}

	return fmt.Errorf(
		"rule %s: threshold default %d is not among its choices", rule, t.Default)
}

func joinWords() string {
	words := make([]string, 0, len(Joins))
	for w := range Joins {
		words = append(words, w)
	}

	sort.Strings(words)

	return strings.Join(words, ", ")
}

func scopeWords() string {
	words := make([]string, 0, len(Scopes))
	for w := range Scopes {
		words = append(words, w)
	}

	sort.Strings(words)

	return strings.Join(words, ", ")
}
