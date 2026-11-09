package processing

import (
	"sort"
	"strconv"
	"time"

	"github.com/drduh/mess/internal/pids"
)

// PNode is one name under one parent, with every process that matched folded into it.
type PNode struct {
	ID    string    `json:"id"`    // path from the root: "77050/zsh/git"
	Name  string    `json:"name"`  // command name of the last image
	Procs int       `json:"procs"` // processes folded here
	Execs int       `json:"execs"` // execs made between them
	Under int       `json:"under"` // processes below this node
	UIDs  []uint32  `json:"uids"`  // accounts they ran as
	TTY   bool      `json:"tty"`   // if they had a terminal
	Paths []string  `json:"paths"` // distinct images
	Sids  []int     `json:"sids"`  // terminal sessions they belonged to
	Pids  []int     `json:"pids"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Kids  []PNode   `json:"kids"`
}

// PRoot groups processes by an unseen parent pid.
type PRoot struct {
	PPID   int     `json:"ppid"`
	Kids   []PNode `json:"kids"`
	Caller string  `json:"caller,omitempty"`
}

// ProcTree is the whole fold.
type ProcTree struct {
	Roots   []PRoot `json:"roots"`
	Procs   int     `json:"procs"`   // processes folded
	Nodes   int     `json:"nodes"`   // nodes emitted
	Deepest int     `json:"deepest"` // levels
}

type pbuild struct {
	name  string
	procs []*pids.Process
	kids  map[string]*pbuild
	order []string
}

const (
	// maxDepth bounds a pathological chain.
	maxDepth = 64

	// pathCap and pidCap bound what a node carries.
	pathCap = 4
	pidCap  = 8
	sidCap  = 4
)

func (b *pbuild) kid(name string) *pbuild {
	if b.kids == nil {
		b.kids = map[string]*pbuild{}
	}

	k := b.kids[name]
	if k == nil {
		k = &pbuild{name: name}
		b.kids[name] = k
		b.order = append(b.order, name)
	}

	return k
}

// commonCaller is the image every process came from, if one.
func commonCaller(ps []*pids.Process) string {
	caller := ""
	for _, p := range ps {
		if p.Caller == "" {
			continue
		}

		if caller == "" {
			caller = p.Caller
		} else if caller != p.Caller {
			return ""
		}
	}

	return caller
}

// BuildProcTree folds window events into the tree.
func BuildProcTree(c pids.Capture) ProcTree {
	byPID := c.Index
	if len(byPID.All) == 0 {
		return ProcTree{Roots: []PRoot{}}
	}
	list := byPID.All

	// The parent held the ppid when the child started.
	parentOf := func(p *pids.Process) *pids.Process {
		return byPID.At(p.PPID, p.First, p, func(cand *pids.Process) bool {
			return pids.CouldHaveForked(cand, p)
		})
	}

	// Children of each process, and roots grouped by pid.
	kids := map[*pids.Process][]*pids.Process{}
	rootsByPPID := map[int][]*pids.Process{}
	for _, p := range list {
		if parent := parentOf(p); parent != nil {
			kids[parent] = append(kids[parent], p)
		} else {
			rootsByPPID[p.PPID] = append(rootsByPPID[p.PPID], p)
		}
	}

	var fold func(b *pbuild, ps []*pids.Process, depth int)
	fold = func(b *pbuild, ps []*pids.Process, depth int) {
		for _, p := range ps {
			k := b.kid(p.Name)
			k.procs = append(k.procs, p)
			if depth < maxDepth {
				fold(k, kids[p], depth+1)
			}
		}
	}

	ppids := make([]int, 0, len(rootsByPPID))
	for ppid := range rootsByPPID {
		ppids = append(ppids, ppid)
	}
	sort.Ints(ppids)

	t := ProcTree{Roots: make([]PRoot, 0, len(ppids)), Procs: len(byPID.All)}
	for _, ppid := range ppids {
		top := &pbuild{}
		fold(top, rootsByPPID[ppid], 0)
		root := PRoot{
			PPID: ppid,
			Kids: emit(top, strconv.Itoa(ppid), &t, 1),
			Caller: commonCaller(rootsByPPID[ppid]),
		}
		t.Roots = append(t.Roots, root)
	}

	// Busiest group first.
	sort.SliceStable(t.Roots, func(i, j int) bool {
		return under(t.Roots[i].Kids) > under(t.Roots[j].Kids)
	})

	return t
}

func under(ns []PNode) int {
	n := 0
	for _, k := range ns {
		n += k.Procs + k.Under
	}

	return n
}

// emit turns the builder into the wire shape, summing as it unwinds.
func emit(b *pbuild, prefix string, t *ProcTree, depth int) []PNode {
	if len(b.order) == 0 {
		return []PNode{}
	}

	if depth > t.Deepest {
		t.Deepest = depth
	}

	out := make([]PNode, 0, len(b.order))
	for _, name := range b.order {
		k := b.kids[name]
		n := PNode{
			ID:    prefix + "/" + name,
			Name:  name,
			Procs: len(k.procs),
			Paths: []string{},
			Pids:  []int{},
			Sids:  []int{},
			UIDs:  []uint32{},
		}

		seenPath := map[string]bool{}
		seenUID := map[uint32]bool{}
		seenSID := map[int]bool{}

		for _, p := range k.procs {
			n.Execs += p.Execs

			if n.First.IsZero() || p.First.Before(n.First) {
				n.First = p.First
			}

			if p.Last.After(n.Last) {
				n.Last = p.Last
			}

			if p.TTY != "" {
				n.TTY = true
			}

			if !seenUID[p.UID] {
				seenUID[p.UID] = true
				n.UIDs = append(n.UIDs, p.UID)
			}

			if p.Path != "" && !seenPath[p.Path] && len(n.Paths) < pathCap {
				seenPath[p.Path] = true
				n.Paths = append(n.Paths, p.Path)
			}

			if len(n.Pids) < pidCap {
				n.Pids = append(n.Pids, p.PID)
			}

			if p.SID != 0 && !seenSID[p.SID] && len(n.Sids) < sidCap {
				seenSID[p.SID] = true
				n.Sids = append(n.Sids, p.SID)
			}
		}
		sort.Slice(n.UIDs, func(i, j int) bool { return n.UIDs[i] < n.UIDs[j] })

		n.Kids = emit(k, n.ID, t, depth+1)
		n.Under = under(n.Kids)
		t.Nodes++

		out = append(out, n)
	}

	// Busiest first, then by name.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Procs+a.Under != b.Procs+b.Under {
			return a.Procs+a.Under > b.Procs+b.Under
		}

		return a.Name < b.Name
	})

	return out
}
