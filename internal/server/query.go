// Event query language.
package server

import (
	"strconv"
	"strings"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
)

// clauses are the conditions of one half of a query.
type clauses struct {
	text    []string
	uids    []uint32
	sids    []int
	pids    []int      // the process itself or its parent: pid: matches either side
	rpids   []int      // the responsible process, who macOS attributes the work to
	seqs    []seqRange // eslogger's own numbering, exact or a span
	caller  []string
	started []string
	sign    []string
	team    []string
	cdhash  []string // the head of a code hash, as a row prints it
	signed  []string
	from    time.Time // events at or after this moment
	to      time.Time // events strictly before it
	any     bool
}

// seqRange is an inclusive span of eslogger sequence numbers.
type seqRange struct{ lo, hi int64 }

func (r seqRange) holds(n int64) bool { return n >= r.lo && n <= r.hi }

// query is what to keep and what to drop.
type query struct {
	keep, drop clauses
}

// parseQuery splits a query into keep and drop clauses.
func parseQuery(raw string) query {
	var q query
	for _, term := range strings.Fields(raw) {
		into := &q.keep
		if rest, cut := strings.CutPrefix(term, "-"); cut && strings.Contains(rest, ":") {
			into, term = &q.drop, rest
		}
		into.add(term)
	}

	return q
}

// add reads one term.
func (c *clauses) add(term string) {
	c.any = true
	field, value, ok := strings.Cut(term, ":")
	if !ok || value == "" {
		c.text = append(c.text, strings.ToLower(term))
		return
	}

	asText := func() { c.text = append(c.text, strings.ToLower(term)) }
	lower := strings.ToLower(value)
	switch strings.ToLower(field) {
	case "uid":
		uid, ok := event.ParseUID(value)
		if !ok {
			asText()
			return
		}
		c.uids = append(c.uids, uid)
	case "sid":
		n, err := strconv.Atoi(value)
		if err != nil {
			asText()
			return
		}
		c.sids = append(c.sids, n)
	case "pid":
		// The process itself or its children.
		n, err := strconv.Atoi(value)
		if err != nil {
			asText()
			return
		}
		c.pids = append(c.pids, n)
	case "rpid":
		n, err := strconv.Atoi(value)
		if err != nil {
			asText()
			return
		}
		c.rpids = append(c.rpids, n)
	case "seq":
		r, ok := parseSeq(value)
		if !ok {
			asText()
			return
		}
		c.seqs = append(c.seqs, r)
	case "caller":
		c.caller = append(c.caller, lower)
	case "started", "image":
		c.started = append(c.started, lower)
	case "sign", "signing":
		c.sign = append(c.sign, lower)
	case "team":
		c.team = append(c.team, lower)
	case "cdhash":
		c.cdhash = append(c.cdhash, lower)
	case "signed":
		c.signed = append(c.signed, lower)
	case "from", "to":
		// An interval from a picked chart column.
		at, err := time.Parse(time.RFC3339, value)
		if err != nil {
			asText()
			return
		}
		if strings.EqualFold(field, "from") {
			c.from = at
		} else {
			c.to = at
		}
	default:
		asText()
	}
}

func (q query) match(e event.Event) bool {
	if q.drop.any && q.drop.hits(e) {
		return false
	}

	return !q.keep.any || q.keep.holds(e)
}

// holds requires every clause to match.
func (c clauses) holds(e event.Event) bool {
	if !inSlice(e.Time, c.from, c.to) {
		return false
	}
	if len(c.uids) > 0 && !hasUID(c.uids, e.UID) {
		return false
	}
	if len(c.sids) > 0 && !hasInt(c.sids, e.SID) {
		return false
	}
	if len(c.pids) > 0 && !hasInt(c.pids, e.PID) && !hasInt(c.pids, e.PPID) {
		return false
	}
	if len(c.rpids) > 0 && !hasInt(c.rpids, e.RPID) {
		return false
	}
	if len(c.seqs) > 0 && !hasSeq(c.seqs, e.Seq) {
		return false
	}
	if len(c.caller) > 0 && !anyIn(c.caller, e.Path, classify.Command(e.Path)) {
		return false
	}
	if len(c.started) > 0 && !anyIn(c.started, started(e)...) {
		return false
	}
	if len(c.sign) > 0 && !anyIn(c.sign, e.Sign, e.Target.Sign) {
		return false
	}
	if len(c.team) > 0 && !anyIn(c.team, e.Team, e.Target.Team) {
		return false
	}
	if len(c.cdhash) > 0 && !hashIn(c.cdhash, e.Target.CDHash) {
		return false
	}
	if len(c.signed) > 0 && !hasValue(c.signed, signedAs(e)) {
		return false
	}
	for _, want := range c.text {
		if !strings.Contains(haystack(e), want) {
			return false
		}
	}

	return true
}

// hits reports whether any clause matches.
func (c clauses) hits(e event.Event) bool {
	if !c.from.IsZero() || !c.to.IsZero() {
		if inSlice(e.Time, c.from, c.to) {
			return true
		}
	}
	if hasUID(c.uids, e.UID) ||
		hasInt(c.sids, e.SID) ||
		hasInt(c.pids, e.PID) || hasInt(c.pids, e.PPID) ||
		hasInt(c.rpids, e.RPID) ||
		hasSeq(c.seqs, e.Seq) ||
		anyIn(c.caller, e.Path, classify.Command(e.Path)) ||
		anyIn(c.started, started(e)...) ||
		anyIn(c.sign, e.Sign, e.Target.Sign) ||
		anyIn(c.team, e.Team, e.Target.Team) ||
		hashIn(c.cdhash, e.Target.CDHash) ||
		hasValue(c.signed, signedAs(e)) {
		return true
	}
	for _, want := range c.text {
		if strings.Contains(haystack(e), want) {
			return true
		}
	}

	return false
}

// started is every name the image goes by.
func started(e event.Event) []string {
	img := e.Image()

	return []string{img, classify.Command(img), e.Argv0()}
}

// haystack is everything a bare word can match.
func haystack(e event.Event) string {
	return strings.ToLower(e.Path + " " + e.Target.Path + " " + e.Script + " " +
		strings.Join(e.Cmd, " ") + " " + e.CWD + " " + strings.Join(e.Env, " ") +
		" " + e.Sign + " " + e.Team + " " + e.Target.Sign + " " + e.Target.Team +
		" " + e.ResolvedArgv0())
}

// hashIn is whether a code hash begins with any of the heads asked for.
func hashIn(heads []string, hash string) bool {
	if hash == "" {
		return false
	}

	hash = strings.ToLower(hash)
	for _, h := range heads {
		if strings.HasPrefix(hash, h) {
			return true
		}
	}

	return false
}

// signedAs is apple, third or unsigned for the started binary.
func signedAs(e event.Event) string {
	sys, team := e.Sys, e.Team
	if e.Target.Known() {
		sys, team = e.Target.Sys, e.Target.Team
	}

	switch {
	case sys:
		return "apple"
	case team == "":
		return "unsigned"
	default:
		return "third"
	}
}

// inSlice is the half-open interval [from, to).
func inSlice(at, from, to time.Time) bool {
	if !from.IsZero() && at.Before(from) {
		return false
	}
	if !to.IsZero() && !at.Before(to) {
		return false
	}

	return true
}

// parseSeq reads "907" or "900-910".
func parseSeq(value string) (seqRange, bool) {
	lo, hi, ok := strings.Cut(value, "-")
	if !ok {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return seqRange{}, false
		}
		return seqRange{n, n}, true
	}

	a, err := strconv.ParseInt(lo, 10, 64)
	if err != nil {
		return seqRange{}, false
	}
	b, err := strconv.ParseInt(hi, 10, 64)
	if err != nil {
		return seqRange{}, false
	}
	if a > b {
		a, b = b, a
	}

	return seqRange{a, b}, true
}

// hasSeq is whether n falls in any span.
func hasSeq(want []seqRange, n int64) bool {
	if n == 0 {
		return false
	}
	for _, w := range want {
		if w.holds(n) {
			return true
		}
	}

	return false
}

func hasInt(want []int, n int) bool {
	for _, w := range want {
		if w == n {
			return true
		}
	}

	return false
}

func hasUID(want []uint32, uid uint32) bool {
	for _, w := range want {
		if w == uid {
			return true
		}
	}

	return false
}

// hasValue matches whole values.
func hasValue(want []string, have string) bool {
	for _, w := range want {
		if w == have {
			return true
		}
	}

	return false
}

// anyIn reports whether any wanted value is a substring of any field.
func anyIn(want []string, fields ...string) bool {
	for _, w := range want {
		for _, f := range fields {
			if f != "" && strings.Contains(strings.ToLower(f), w) {
				return true
			}
		}
	}

	return false
}
