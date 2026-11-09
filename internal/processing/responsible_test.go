package processing

import (
	"testing"
	"time"

	"github.com/drduh/mess/internal/event"
)

// XPC service whose responsible process is the asking app.
func responsibleFixture() []event.Event {
	base := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)

	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	mk := func(s, pid, ppid, rpid int, caller, image, cmd string) event.Event {
		return event.Event{
			Time: at(s), PID: pid, PPID: ppid, RPID: rpid,
			Path: caller, Target: event.Target{Path: image}, Cmd: []string{cmd},
		}
	}

	return []event.Event{
		mk(0, 500, 1, 500, "/usr/libexec/xpcproxy",
			"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
			"Terminal"),
		mk(10, 900, 1, 500, "/usr/libexec/xpcproxy",
			"/System/Library/X.xpc/Contents/MacOS/helper",
			"helper"),
		mk(20, 901, 1, 500, "/usr/libexec/xpcproxy",
			"/System/Library/X.xpc/Contents/MacOS/helper",
			"helper"),
		mk(100, 500, 1, 500, "/usr/libexec/xpcproxy",
			"/System/Applications/Mail.app/Contents/MacOS/Mail",
			"Mail"),
		mk(110, 902, 1, 500, "/usr/libexec/xpcproxy",
			"/System/Library/X.xpc/Contents/MacOS/helper",
			"helper"),
		mk(120, 903, 1, 903, "/usr/libexec/xpcproxy",
			"/System/Library/X.xpc/Contents/MacOS/helper",
			"helper"),
		mk(130, 904, 1, 77, "/usr/libexec/xpcproxy",
			"/System/Library/X.xpc/Contents/MacOS/helper",
			"helper"),
	}
}

func TestResponsibleNamesTheRequester(t *testing.T) {
	got, self, unnamed := Responsible(responsibleFixture(), "helper", 5)

	if self != 1 {
		t.Errorf(
			"self = %d, want the one launch responsible for itself", self)
	}

	if unnamed != 1 {
		t.Errorf(
			"unnamed = %d, want the one whose pid the log never saw", unnamed)
	}

	if len(got) != 2 {
		t.Fatalf("requesters = %+v, want Terminal and Mail", got)
	}

	if got[0].Name != "Terminal" || got[0].N != 2 {
		t.Errorf("first = %+v, want Terminal twice", got[0])
	}

	if got[1].Name != "Mail" || got[1].N != 1 {
		t.Errorf("second = %+v, want Mail once", got[1])
	}

	if got[0].PID != 500 || got[1].PID != 500 {
		t.Errorf("both held pid 500: %+v", got)
	}
}

// Binary nothing asked for and one that never ran.
func TestResponsibleSaysNothingWhereThereIsNothing(t *testing.T) {
	got, self, unnamed := Responsible(responsibleFixture(), "Terminal", 5)
	if len(got) != 0 || self != 1 || unnamed != 0 {
		t.Errorf("Terminal answered for itself: got %+v self=%d unnamed=%d",
			got, self, unnamed)
	}

	if got, self, unnamed := Responsible(
		responsibleFixture(), "nosuch", 5); len(
		got) != 0 || self != 0 || unnamed != 0 {
		t.Errorf("a binary that never ran: %+v %d %d", got, self, unnamed)
	}
}

// Pid image comes from its execs, not folded processes.
func TestImageOfAPidDependsOnWhen(t *testing.T) {
	by := ranAt(responsibleFixture())
	base := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)

	if img, ok := imageOf(by, 500, base.Add(
		10*time.Second)); !ok || img != "Terminal" {
		t.Errorf("pid 500 at +10s = %q, %v; want Terminal", img, ok)
	}

	if img, ok := imageOf(by, 500, base.Add(
		110*time.Second)); !ok || img != "Mail" {
		t.Errorf("pid 500 at +110s = %q, %v; want Mail", img, ok)
	}

	if _, ok := imageOf(by, 500, base.Add(-time.Second)); ok {
		t.Error("pid 500 before its first exec should name nothing")
	}

	if _, ok := imageOf(by, 4242, base); ok {
		t.Error("a pid the log never saw should name nothing")
	}
}
