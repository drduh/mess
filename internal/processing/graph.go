package processing

import (
	"strconv"
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/tally"
)

// Graph relates binaries by who launched whom.
type Graph struct {
	Nodes    map[string]*Node
	Origins  map[string]string
	children map[string]tally.Counter
	parents  map[string]tally.Counter
}

// Node is a binary in the graph.
type Node struct {
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	Origins     []string  `json:"origins"`
	Category    string    `json:"category"`
	Kind        string    `json:"kind"`
	Vendor      string    `json:"vendor"`
	AsCaller    int       `json:"asCaller"` // called exec
	AsImage     int       `json:"asImage"`  // was launched
	Platform    int       `json:"platform"`
	NonPlatform int       `json:"nonPlatform"`
	Unsigned    int       `json:"unsigned"`
	AsRoot      int       `json:"asRoot"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
	Parents     int       `json:"parents"`
	Children    int       `json:"children"`
	CallerPaths []Count   `json:"callerPaths"`
	ImageArgs   []Count   `json:"imageArgs"`
	Signers     []Count   `json:"signers"`
	UIDs        []Count   `json:"uids"`
	Archs       []Count   `json:"archs"`
	Translated  int       `json:"translated"` // ran under Rosetta
	Scripts     []Count   `json:"scripts"`
	Counts      []int     `json:"counts"` // activity per bucket
	Peak        int       `json:"peak"`
}

// BuildGraph walks events and assembles the graph.
func BuildGraph(events []event.Event) *Graph {
	b := newGraphBuild()

	for i := range events {
		e := &events[i]
		caller := b.calling(e)
		started := b.started(e)
		add(b.g.children, caller, started)
		add(b.g.parents, started, caller)
	}

	return b.finish()
}

type graphBuild struct {
	g           *Graph
	names       *labeller
	labels      *classify.Memo
	callerPaths map[string]tally.Counter
	imageArgs   map[string]tally.Counter
	signers     map[string]tally.Counter
	uids        map[string]tally.Counter
	archs       map[string]tally.Counter
	cats        map[string]tally.Counter
	kinds       map[string]tally.Counter
	vendors     map[string]tally.Counter
	scripts     map[string]tally.Counter
}

func newGraphBuild() *graphBuild {
	counter := func() map[string]tally.Counter { return map[string]tally.Counter{} }
	return &graphBuild{
		g: &Graph{
			Nodes:    map[string]*Node{},
			Origins:  map[string]string{},
			children: counter(),
			parents:  counter(),
		},
		callerPaths: counter(),
		imageArgs:   counter(),
		signers:     counter(),
		uids:        counter(),
		archs:       counter(),
		cats:        counter(),
		kinds:       counter(),
		vendors:     counter(),
		scripts:     counter(),
		labels:      classify.NewMemo(),
		names:       newLabeller(),
	}
}

// calling records the side that called exec.
func (b *graphBuild) calling(e *event.Event) string {
	name := classify.Command(e.Path)
	n := b.g.node(name)
	n.AsCaller++
	n.seen(e.Time)

	b.provenance(n, e.Sys, e.Team, e.UID)
	b.where(name, e.Path)
	add(b.signers, name, b.names.caller(e))
	b.account(name, e.UID)
	b.describe(name, e.Path, e.Sign)

	return name
}

// started records the side that was launched.
func (b *graphBuild) started(e *event.Event) string {
	img := e.Image()
	name := classify.Command(img)
	n := b.g.node(name)
	n.AsImage++
	n.seen(e.Time)
	add(b.imageArgs, name, e.Argv0())

	if e.Script != "" {
		add(b.scripts, name, e.Script)
	}

	if a := classify.Arch(e.CPU); a != "" {
		add(b.archs, name, a)
		if a == classify.ArchX86_64 {
			n.Translated++
		}
	}

	if t := e.Target; t.Known() {
		b.provenance(n, t.Sys, t.Team, t.UID)
		b.where(name, t.Path)
		add(b.signers, name, b.names.image(e))
		b.account(name, t.UID)
		b.describe(name, t.Path, t.Sign)
	} else {
		b.describe(name, img, "")
	}

	return name
}

func (b *graphBuild) describe(name, path, sign string) {
	l := b.labels.Of(name, path, sign)
	if l.Category != "" {
		add(b.cats, name, l.Category)
	}

	if l.Kind != "" {
		add(b.kinds, name, l.Kind)
	}

	if l.Vendor != "" {
		add(b.vendors, name, l.Vendor)
	}
}

// where records the classified origin path.
func (b *graphBuild) where(name, path string) {
	add(b.callerPaths, name, path)
	if _, seen := b.g.Origins[path]; !seen {
		if o := classify.Origin(path); o != "" {
			b.g.Origins[path] = o
		}
	}
}

func (b *graphBuild) account(name string, uid uint32) {
	add(b.uids, name, "uid "+strconv.FormatUint(uint64(uid), 10))
}

// provenance counts who vouched for a binary on one event.
func (b *graphBuild) provenance(n *Node, sys bool, team string, uid uint32) {
	if sys {
		n.Platform++
	} else {
		n.NonPlatform++

		if team == "" {
			n.Unsigned++
		}
	}

	if uid == 0 {
		n.AsRoot++
	}
}

// finish takes the top of every counter onto the node it belongs to.
func (b *graphBuild) finish() *Graph {
	const detail = 12

	for name, n := range b.g.Nodes {
		n.CallerPaths = b.callerPaths[name].Top(detail)
		n.ImageArgs = b.imageArgs[name].Top(detail)
		n.Signers = b.signers[name].Top(detail)
		n.UIDs = b.uids[name].Top(detail)
		n.Scripts = b.scripts[name].Top(detail)
		n.Archs = b.archs[name].Top(detail)
		n.Category = first(b.cats[name])
		n.Kind = first(b.kinds[name])
		n.Vendor = first(b.vendors[name])
		n.Parents = len(b.g.parents[name])
		n.Children = len(b.g.children[name])
		n.Origins = b.originsOf(name)
	}

	return b.g
}

// first is the busiest entry of a counter.
func first(c tally.Counter) string {
	if top := c.Top(1); len(top) > 0 {
		return top[0].Key
	}

	return ""
}

// originsOf is the kinds of place a binary lives in.
func (b *graphBuild) originsOf(name string) []string {
	out := []string{}
	seen := map[string]bool{}

	paths := b.callerPaths[name]
	for _, c := range paths.Top(len(paths)) {
		if o := b.g.Origins[c.Key]; o != "" && !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}

	return out
}

// ChildrenOf returns binaries this one launched, most frequent first.
func (g *Graph) ChildrenOf(name string, n int) []Count {
	return g.children[name].Top(n)
}

// ParentsOf returns binaries that launched this one.
func (g *Graph) ParentsOf(name string, n int) []Count {
	return g.parents[name].Top(n)
}

// Summaries lists every node, ordered by total activity.
func (g *Graph) Summaries() []*Node {
	out := make([]*Node, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		out = append(out, n)
	}

	sortNodes(out)

	return out
}

// seen widens the window a binary was active in.
func (n *Node) seen(at time.Time) {
	if n.First.IsZero() || at.Before(n.First) {
		n.First = at
	}

	if at.After(n.Last) {
		n.Last = at
	}
}

func (g *Graph) node(name string) *Node {
	n := g.Nodes[name]
	if n == nil {
		n = &Node{
			Name:    name,
			Role:    classify.Role(name),
			Origins: []string{},
		}

		g.Nodes[name] = n
	}

	return n
}

// add increments a key inside a nested counter map.
func add(m map[string]tally.Counter, outer, inner string) {
	c := m[outer]

	if c == nil {
		c = tally.Counter{}
		m[outer] = c
	}

	c.Add(inner)
}

// NodeActivity fills each binary count across the capture window.
func NodeActivity(g *Graph, events []event.Event, start, end time.Time, buckets int) {
	if buckets < 1 || g == nil {
		return
	}

	span := end.Sub(start)
	if span <= 0 {
		span = time.Second
	}

	index := bucketer(start, span, buckets)

	for _, n := range g.Nodes {
		n.Counts = make([]int, buckets)
	}

	for _, e := range events {
		at := index(e.Time)
		if n := g.Nodes[classify.Command(e.Path)]; n != nil {
			n.Counts[at]++
		}

		if n := g.Nodes[classify.Command(e.Image())]; n != nil {
			n.Counts[at]++
		}
	}

	for _, n := range g.Nodes {
		for _, c := range n.Counts {
			if c > n.Peak {
				n.Peak = c
			}
		}
	}
}
