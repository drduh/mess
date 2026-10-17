package server

import (
	"testing"
	"time"

	"github.com/drduh/mess/internal/event"
)

func ev(path, sign, team string, sys bool, uid uint32, cmd ...string) event.Event {
	return event.Event{Time: base, UID: uid, Sys: sys, Team: team, Sign: sign, Path: path, Cmd: cmd}
}

func TestQuery(t *testing.T) {
	// The three signing states, which are not simply "has a team".
	apple := ev("/usr/libexec/xpcproxy", "com.apple.xpc.proxy", "", true, 0, "contactsd")
	third := ev("/usr/local/go/bin/go", "org.golang.go", "EQHXZ8M8AV", false, 501, "compile")
	nosig := ev("/opt/homebrew/bin/brew", "brew", "", false, 0, "curl", "-fsSL")
	nosig.Target = event.Target{Path: "/opt/homebrew/bin/curl", Sign: "se.haxx.curl", Team: "G2S7P7J672"}
	nosig.CWD = "/Users/someone/Downloads"
	nosig.SID = 68666
	nosig.Env = []string{"DYLD_INSERT_LIBRARIES=/tmp/x.dylib"}
	// third is pid 720 and nosig is its child, done on third's behalf.
	third.PID, nosig.PPID = 720, 720
	nosig.PID = 721
	nosig.RPID = 720

	cases := []struct {
		q    string
		want []bool // apple, third, nosig
	}{
		{"", []bool{true, true, true}},
		{"caller:xpcproxy", []bool{true, false, false}},
		{"-caller:xpcproxy", []bool{false, true, true}},
		{"-started:contactsd", []bool{false, true, true}},
		// signed: reads the target, not the caller.
		{"signed:apple", []bool{true, false, false}},
		{"signed:third", []bool{false, true, true}},
		{"signed:unsigned", []bool{false, false, false}},
		{"-signed:apple", []bool{false, true, true}},
		{"-signed:apple -signed:third", []bool{false, false, false}},
		{"uid:0 -caller:xpcproxy", []bool{false, false, true}},
		{"-uid:0", []bool{false, true, false}},
		{"uid:0 uid:501", []bool{true, true, true}},
		// A leading dash on a bare word is a search, not an exclusion.
		{"-fsSL", []bool{false, false, true}},
		{"-Pni", []bool{false, false, false}},
		// Unknown fields and unreadable values fall back to text.
		{"-nosuchfield:x", []bool{true, true, true}},
		{"uid:root", []bool{false, false, false}},
		// The target side, where the log has it.
		{"started:/opt/homebrew/bin/curl", []bool{false, false, true}},
		{"image:curl", []bool{false, false, true}},
		{"sign:se.haxx", []bool{false, false, true}},
		{"team:g2s7", []bool{false, false, true}},
		{"sid:68666", []bool{false, false, true}},
		{"-sid:68666", []bool{true, true, false}},
		{"sid:6866", []bool{false, false, false}}, // whole, not a prefix
		// pid: is the process's own exec and its children.
		{"pid:720", []bool{false, true, true}},
		{"pid:721", []bool{false, false, true}},
		{"-pid:720", []bool{true, false, false}},
		{"pid:x", []bool{false, false, false}},
		// rpid: is what one process was held responsible for.
		{"rpid:720", []bool{false, false, true}},
		{"-rpid:720", []bool{true, true, false}},
		{"rpid:x", []bool{false, false, false}},
		// Bare words reach cwd and the kept environment.
		{"downloads", []bool{false, false, true}},
		{"dyld_insert", []bool{false, false, true}},
		{"CURL downloads", []bool{false, false, true}},
	}
	for _, c := range cases {
		q := parseQuery(c.q)
		got := []bool{q.match(apple), q.match(third), q.match(nosig)}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("query %q event %d = %v, want %v", c.q, i, got[i], c.want[i])
			}
		}
	}
}

// from: and to: bound a half-open interval.
func TestQueryInterval(t *testing.T) {
	at := func(min int) time.Time { return time.Date(2026, 9, 10, 9, min, 0, 0, time.UTC) }
	mk := func(min int) event.Event { return event.Event{Time: at(min), Cmd: []string{"ls"}} }

	q := parseQuery("from:2026-09-10T09:05:00Z to:2026-09-10T09:10:00Z")
	for _, c := range []struct {
		min  int
		want bool
	}{{4, false}, {5, true}, {9, true}, {10, false}, {11, false}} {
		if got := q.match(mk(c.min)); got != c.want {
			t.Errorf("09:%02d matched %v, want %v", c.min, got, c.want)
		}
	}

	// Negated, the interval is one clause: what falls inside it goes.
	q = parseQuery("-from:2026-09-10T09:05:00Z -to:2026-09-10T09:10:00Z")
	for _, c := range []struct {
		min  int
		want bool
	}{{4, true}, {5, false}, {9, false}, {10, true}} {
		if got := q.match(mk(c.min)); got != c.want {
			t.Errorf("negated: 09:%02d matched %v, want %v", c.min, got, c.want)
		}
	}

	// A value that is not a time is a search for that text.
	if q := parseQuery("from:yesterday"); !q.keep.from.IsZero() || len(q.keep.text) != 1 {
		t.Errorf("from:yesterday = %+v, want a text search", q.keep)
	}
}

func TestSeqQuery(t *testing.T) {
	var events []event.Event
	for i := int64(1); i <= 8; i++ {
		events = append(events, event.Event{Seq: i, Cmd: []string{"ls"}})
	}
	events = append(events, event.Event{Cmd: []string{"old"}}) // a log with no numbering

	seqs := func(raw string) []int64 {
		q := parseQuery(raw)
		var got []int64
		for _, e := range events {
			if q.match(e) {
				got = append(got, e.Seq)
			}
		}
		return got
	}

	if got := seqs("seq:3"); len(got) != 1 || got[0] != 3 {
		t.Errorf("seq:3 = %v, want exactly [3]", got)
	}
	if got := seqs("seq:3-5"); len(got) != 3 {
		t.Errorf("seq:3-5 = %v, want three events", got)
	}
	if a, b := seqs("seq:5-3"), seqs("seq:3-5"); len(a) != len(b) {
		t.Errorf("seq:5-3 = %v, seq:3-5 = %v; a span has no direction", a, b)
	}
	if got := seqs("seq:3 seq:5"); len(got) != 2 {
		t.Errorf("seq:3 seq:5 = %v, want both", got)
	}
	if got := seqs("seq:banana"); len(got) != 0 {
		t.Errorf("seq:banana matched %v; it should fall through to text", got)
	}
	if got := seqs("seq:0"); len(got) != 0 {
		t.Errorf("seq:0 matched %v; an unnumbered event is in no span", got)
	}
	if got := seqs("-seq:3"); len(got) != len(events)-1 {
		t.Errorf("-seq:3 kept %d of %d", len(got), len(events))
	}
}

// cdhash: matches a hash head; argv[0] matches where it resolved.
func TestQueryReachesWhatFindingsPrint(t *testing.T) {
	built := event.Event{Path: "/bin/zsh", CWD: "/tmp", Cmd: []string{"./build/tool"},
		Target: event.Target{Path: "/private/tmp/build/tool", CDHash: "aaaa1111bbbb2222cccc3333dddd4444eeee5555"}}
	other := event.Event{Path: "/bin/zsh", CWD: "/Users/p/src", Cmd: []string{"tool"},
		Target: event.Target{Path: "/usr/local/bin/tool", CDHash: "ffff0000"}}

	for _, c := range []struct {
		q           string
		built, want bool
	}{
		{"cdhash:aaaa1111bbbb", true, true},
		{"cdhash:AAAA1111", true, true},
		{"cdhash:aaaa1111", false, false},
		{"-cdhash:aaaa1111", true, false},
		{"-cdhash:aaaa1111", false, true},
		{"/tmp/build/tool", true, true},
		{"/tmp/build/tool", false, false},
		{"/private/tmp", true, true},
	} {
		e := built
		if !c.built {
			e = other
		}
		if got := parseQuery(c.q).match(e); got != c.want {
			t.Errorf("%q on the %s event = %v, want %v", c.q,
				map[bool]string{true: "built", false: "other"}[c.built], got, c.want)
		}
	}

	// Without a target, only the resolved argv[0] has the path.
	old := event.Event{Path: "/bin/zsh", CWD: "/tmp", Cmd: []string{"./build/tool"}}
	if !parseQuery("/tmp/build/tool").match(old) {
		t.Error("a relative argv[0] is not searchable by where it resolved to")
	}
	if parseQuery("/tmp/build/tool").match(event.Event{Path: "/bin/zsh", Cmd: []string{"./build/tool"}}) {
		t.Error("with no cwd there is nothing to resolve against")
	}
}
