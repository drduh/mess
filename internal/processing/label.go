package processing

import "github.com/drduh/mess/internal/event"

type labeller struct {
	signers map[signKey]string
	pairs   map[pairKey]string
}

type signKey struct {
	sign, team string
	sys        bool
}

type pairKey struct{ from, to string }

func newLabeller() *labeller {
	return &labeller{
		signers: map[signKey]string{},
		pairs:   map[pairKey]string{},
	}
}

// label is the display name for a signing identity.
func (l *labeller) label(sign, team string, sys bool) string {
	k := signKey{sign, team, sys}
	if got, ok := l.signers[k]; ok {
		return got
	}

	out := signerLabel(sign, team, sys)
	l.signers[k] = out

	return out
}

// caller names who called exec.
func (l *labeller) caller(e *event.Event) string {
	return l.label(e.Sign, e.Team, e.Sys)
}

// image names the started binary.
func (l *labeller) image(e *event.Event) string {
	return l.label(e.Target.Sign, e.Target.Team, e.Target.Sys)
}

// lineage is the caller to image association.
func (l *labeller) lineage(from, to string) string {
	k := pairKey{from, to}
	if got, ok := l.pairs[k]; ok {
		return got
	}

	out := from + " -> " + to
	l.pairs[k] = out

	return out
}
