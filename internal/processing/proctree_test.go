package processing

import (
	"testing"
	"time"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
)

func pat(min int) time.Time { return time.Date(2026, 11, 8, 9, min, 0, 0, time.UTC) }

// ev is one exec: pid became image, started by ppid.
func ev(min, pid, ppid int, image string, opts ...func(*event.Event)) event.Event {
	e := event.Event{
		Time:   pat(min),
		PID:    pid,
		PPID:   ppid,
		UID:    501,
		Path:   "/bin/zsh",
		Sys:    true,
		Cmd:    []string{image},
		Target: event.Target{Path: image, UID: 501, Sys: true},
	}

	for _, o := range opts {
		o(&e)
	}

	return e
}

// from sets the image that called exec.
func from(path string) func(*event.Event) { return func(e *event.Event) { e.Path = path } }

func tty(s string) func(*event.Event) { return func(e *event.Event) { e.TTY = s } }
func sid(n int) func(*event.Event)    { return func(e *event.Event) { e.SID = n } }
func uid(u uint32) func(*event.Event) {
	return func(e *event.Event) { e.UID = u; e.Target.UID = u }
}

func find(ns []PNode, name string) *PNode {
	for i := range ns {
		if ns[i].Name == name {
			return &ns[i]
		}
	}

	return nil
}

// Siblings with one name fold into one node.
func TestFoldsSiblingsByName(t *testing.T) {
	var events []event.Event

	events = append(events, ev(0, 500, 400, "/bin/zsh", tty("/dev/ttys001")))
	pid := 600
	for i := 0; i < 300; i++ {
		events = append(events, ev(1, pid, 500, "/bin/ls", tty("/dev/ttys001")))
		pid++
	}

	for i := 0; i < 2; i++ {
		events = append(events, ev(
			2, pid, 500, "/usr/bin/git", tty("/dev/ttys001")))
		events = append(events, ev(
			2, pid+1, pid, "/usr/bin/less", tty("/dev/ttys001"), from("/usr/bin/git")))
		pid += 2
	}
	tr := BuildProcTree(pids.Over(events))

	if len(tr.Roots) != 1 || tr.Roots[0].PPID != 400 {
		t.Fatalf("roots = %+v, want one group under pid 400", tr.Roots)
	}

	zsh := find(tr.Roots[0].Kids, "zsh")
	if zsh == nil || zsh.Procs != 1 {
		t.Fatalf("zsh = %+v", zsh)
	}

	ls := find(zsh.Kids, "ls")
	if ls == nil || ls.Procs != 300 || len(ls.Kids) != 0 {
		t.Errorf("ls = %+v, want 300 processes folded into one leaf", ls)
	}

	git := find(zsh.Kids, "git")
	if git == nil || git.Procs != 2 || git.Under != 2 {
		t.Errorf("git = %+v, want 2 processes holding 2 below", git)
	}

	if less := find(git.Kids, "less"); less == nil || less.Procs != 2 {
		t.Errorf("less = %+v", less)
	}

	if zsh.Under != 304 {
		t.Errorf("zsh holds %d, want 304", zsh.Under)
	}

	if tr.Procs != 305 || tr.Nodes != 4 {
		t.Errorf("%d processes folded to %d nodes, want 305 to 4", tr.Procs, tr.Nodes)
	}

	if tr.Deepest != 3 {
		t.Errorf("deepest = %d, want 3", tr.Deepest)
	}

	if zsh.Kids[0].Name != "ls" {
		t.Errorf("kids = %s…, want ls first", zsh.Kids[0].Name)
	}
}

// A shell that starts a shell nests one level deeper.
func TestSelfNestingIsDepth(t *testing.T) {
	tr := BuildProcTree(pids.Over([]event.Event{
		ev(0, 500, 1, "/bin/zsh"),
		ev(1, 501, 500, "/bin/zsh"),
		ev(2, 502, 501, "/bin/zsh"),
	}))

	n := find(tr.Roots[0].Kids, "zsh")
	for depth := 1; depth <= 3; depth++ {
		if n == nil || n.Procs != 1 {
			t.Fatalf("depth %d: %+v", depth, n)
		}

		if depth < 3 {
			n = find(n.Kids, "zsh")
		}
	}

	if tr.Nodes != 3 || tr.Deepest != 3 {
		t.Errorf("nodes %d deepest %d, want 3 and 3", tr.Nodes, tr.Deepest)
	}
}

// A pid is reused.
func TestReusedPidPicksTheRightParent(t *testing.T) {
	events := []event.Event{
		ev(0, 500, 1, "/bin/zsh"),
		ev(1, 700, 500, "/usr/bin/make"),
		ev(2, 800, 700, "/usr/bin/cc", from("/usr/bin/make")),
		ev(10, 700, 999, "/usr/bin/vim"),
		ev(11, 801, 700, "/usr/bin/git", from("/usr/bin/vim")),
	}

	tr := BuildProcTree(pids.Over(events))
	var zsh, vim *PNode

	for i := range tr.Roots {
		if k := find(tr.Roots[i].Kids, "zsh"); k != nil {
			zsh = k
		}

		if k := find(tr.Roots[i].Kids, "vim"); k != nil {
			vim = k
		}
	}

	if zsh == nil || vim == nil {
		t.Fatalf("roots = %+v", tr.Roots)
	}

	mk := find(zsh.Kids, "make")
	if mk == nil || find(mk.Kids, "cc") == nil {
		t.Errorf("make should hold cc: %+v", mk)
	}

	if find(mk.Kids, "git") != nil {
		t.Error("the make adopted the vim's child")
	}

	if find(vim.Kids, "git") == nil {
		t.Errorf("vim should hold git: %+v", vim)
	}
}

// The process whose life covers the child start wins.
func TestCoveringLifeWinsOverLatestStart(t *testing.T) {
	events := []event.Event{
		ev(0, 900, 1, "/usr/bin/make"),
		ev(20, 900, 1, "/usr/bin/make", from("/usr/bin/make")),
		ev(5, 900, 2, "/usr/bin/vim"),
		ev(10, 950, 900, "/usr/bin/cc", from("/usr/bin/make")),
	}

	tr := BuildProcTree(pids.Over(events))
	var mk *PNode

	for i := range tr.Roots {
		if k := find(tr.Roots[i].Kids, "make"); k != nil {
			mk = k
		}
	}

	if mk == nil || find(mk.Kids, "cc") == nil {
		t.Fatalf("the covering make should hold cc; roots = %+v", tr.Roots)
	}
}

// A reused pid with the same parent.
func TestAPidReusedUnderTheSameParentIsTwoProcesses(t *testing.T) {
	events := []event.Event{
		ev(0, 6760, 1, "/System/Library/CoreServices/UserSelector.app/Contents/MacOS/UserSelector",
			from("/sbin/launchd")),
		ev(3000, 6760, 1, "/bin/zsh", from("/sbin/launchd")),
		ev(3001, 7000, 6760, "/usr/bin/git", from("/bin/zsh")),
		ev(3002, 7001, 6760, "/usr/bin/locale", from("/bin/zsh")),
	}

	tr := BuildProcTree(pids.Over(events))
	var sel, sh *PNode

	for i := range tr.Roots {
		if k := find(tr.Roots[i].Kids, "UserSelector"); k != nil {
			sel = k
		}

		if k := find(tr.Roots[i].Kids, "zsh"); k != nil {
			sh = k
		}
	}

	if sel == nil || sh == nil {
		t.Fatalf("both occupants of the pid should be drawn; roots = %+v", tr.Roots)
	}

	if len(sel.Kids) != 0 {
		t.Errorf("UserSelector started nothing, but holds %+v", sel.Kids)
	}

	if find(sh.Kids, "git") == nil || find(sh.Kids, "locale") == nil {
		t.Errorf("the shell should hold what it ran; it holds %+v", sh.Kids)
	}
}

// A fork that never execs.
func TestAForkOnlyParentIsNotMistakenForADeadOne(t *testing.T) {
	cd := "/System/Library/Frameworks/Contacts.framework/Support/contactsd"
	events := []event.Event{
		ev(0, 5000, 1, "/usr/libexec/xpcproxy", from("/sbin/launchd")),
		ev(0, 5000, 1, cd, from("/usr/libexec/xpcproxy")),
		ev(540, 6000, 4242, "/bin/zsh",
			from("/Applications/Terminal.app/Contents/MacOS/Terminal")),
		ev(541, 7000, 5000, "/bin/ls", from("/bin/zsh")),
		ev(542, 7001, 5000, "/bin/cp", from("/bin/zsh")),
	}

	tr := BuildProcTree(pids.Over(events))
	var daemon *PNode
	var orphans *PRoot

	for i := range tr.Roots {
		if k := find(tr.Roots[i].Kids, "contactsd"); k != nil {
			daemon = k
		}

		if tr.Roots[i].PPID == 5000 {
			orphans = &tr.Roots[i]
		}
	}

	if daemon == nil {
		t.Fatalf("contactsd should be drawn; roots = %+v", tr.Roots)
	}

	if len(daemon.Kids) != 0 {
		t.Errorf("contactsd never ran a shell and must not hold its children: %+v", daemon.Kids)
	}

	if orphans == nil ||
		find(orphans.Kids, "ls") == nil ||
		find(orphans.Kids, "cp") == nil {
		t.Errorf(
			"ls and cp belong to a parent the log never saw, under its pid 5000; roots = %+v", tr.Roots)
	}
}

// A process's own later exec is the same process.
func TestAProcessExecingAgainIsOneProcess(t *testing.T) {
	tr := BuildProcTree(pids.Over([]event.Event{
		ev(0, 500, 1, "/usr/bin/env", from("/bin/zsh")),
		ev(1, 500, 1, "/bin/bash", from("/usr/bin/env")),
		ev(2, 600, 500, "/usr/bin/git", from("/bin/bash")),
	}))

	sh := find(tr.Roots[0].Kids, "bash")
	if sh == nil || sh.Procs != 1 {
		t.Fatalf("env becoming bash is one process; roots = %+v", tr.Roots)
	}

	if find(sh.Kids, "git") == nil {
		t.Errorf("and it holds what it ran: %+v", sh.Kids)
	}
}

// What a node carries about the processes inside it.
func TestNodeCarriesTheFacts(t *testing.T) {
	tr := BuildProcTree(pids.Over([]event.Event{
		ev(0, 500, 1, "/bin/zsh", tty("/dev/ttys001"), sid(500)),
		ev(1, 600, 500, "/usr/bin/sudo", tty("/dev/ttys001"), sid(500)),
		ev(2, 601, 500, "/opt/homebrew/bin/sudo", uid(0), sid(500)),
		ev(9, 602, 500, "/usr/bin/sudo", uid(0), sid(500)),
	}))

	sudo := find(find(tr.Roots[0].Kids, "zsh").Kids, "sudo")
	if sudo.Procs != 3 || sudo.Execs != 3 {
		t.Errorf("sudo = %+v", sudo)
	}

	if len(sudo.UIDs) != 2 || sudo.UIDs[0] != 0 || sudo.UIDs[1] != 501 {
		t.Errorf("uids = %v, want [0 501]", sudo.UIDs)
	}

	if len(sudo.Paths) != 2 {
		t.Errorf("paths = %v, want both images", sudo.Paths)
	}

	if !sudo.TTY {
		t.Error("one of them had a terminal")
	}

	if !sudo.First.Equal(pat(1)) || !sudo.Last.Equal(pat(9)) {
		t.Errorf("span %v to %v", sudo.First, sudo.Last)
	}

	if len(sudo.Pids) != 3 {
		t.Errorf("pids = %v", sudo.Pids)
	}

	if len(sudo.Sids) != 1 || sudo.Sids[0] != 500 {
		t.Errorf("sids = %v, want the one session", sudo.Sids)
	}
}

func TestEmptyTree(t *testing.T) {
	tr := BuildProcTree(pids.Over(nil))
	if tr.Roots == nil || len(tr.Roots) != 0 || tr.Procs != 0 {
		t.Errorf("empty tree = %+v", tr)
	}
}
