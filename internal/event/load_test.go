package event

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
)

// Half-written last line must not fail entire load.
func TestLoadSkipsBadLines(t *testing.T) {
	good := func(sec, pid int) string {
		return fmt.Sprintf(
			`{"time":"2026-09-15T10:00:0%dZ","pid":%d,"cmd":["id"]}`, sec, pid)
	}

	fsys := fstest.MapFS{
		"mess-v1-mac-1.log": &fstest.MapFile{Data: []byte(strings.Join([]string{
			good(0, 100),
			`{"time":"2026-09-15T10:00:01Z","pid":`, // caught mid-flush
			good(2, 102),
			`not json at all`,
			good(3, 103),
		}, "\n") + "\n")},
	}

	got, err := Load(fsys, "mess-v1-*.log")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(got.Events) != 3 {
		t.Errorf("read %d events, want the 3 good ones", len(got.Events))
	}

	if got.BadTotal != 2 {
		t.Errorf("BadTotal = %d, want 2", got.BadTotal)
	}

	if len(got.Bad) != 2 {
		t.Fatalf("kept %d bad lines, want 2", len(got.Bad))
	}

	if got.Bad[0].Line != 2 || got.Bad[1].Line != 4 {
		t.Errorf("bad lines at %d and %d, want 2 and 4", got.Bad[0].Line, got.Bad[1].Line)
	}

	if got.Bad[0].File != "mess-v1-mac-1.log" {
		t.Errorf("bad line file = %q", got.Bad[0].File)
	}

	if got.Bad[1].Text != "not json at all" || got.Bad[1].Why == "" {
		t.Errorf("bad line = %+v, want the text and a reason", got.Bad[1])
	}
}

// The last line of a file still being written has no newline after it.
func TestLoadReadsFinalLineWithoutNewline(t *testing.T) {
	fsys := fstest.MapFS{
		"mess-v1-mac-1.log": &fstest.MapFile{
			Data: []byte(
				`{"time":"2026-09-15T10:00:00Z","pid":1,"cmd":["a"]}` + "\n" +
					`{"time":"2026-09-15T10:00:01Z","pid":2,"cmd":["b"]}`)},
	}

	got, err := Load(fsys, "mess-v1-*.log")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(got.Events) != 2 || got.BadTotal != 0 {
		t.Errorf("read %d events, %d bad; want 2 and 0", len(got.Events), got.BadTotal)
	}
}

// Blank lines are not lines that failed to decode.
func TestLoadIgnoresBlankLines(t *testing.T) {
	fsys := fstest.MapFS{
		"mess-v1-mac-1.log": &fstest.MapFile{
			Data: []byte("\n" + `{"time":"2026-09-15T10:00:00Z","pid":1,"cmd":["a"]}` + "\n\n  \n")},
	}

	got, err := Load(fsys, "mess-v1-*.log")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(got.Events) != 1 || got.BadTotal != 0 {
		t.Errorf("read %d events, %d bad; want 1 and 0", len(got.Events), got.BadTotal)
	}
}

// The count is exact however many there are; the list is a sample.
func TestLoadCapsTheBadLinesItKeeps(t *testing.T) {
	var b strings.Builder
	for i := 0; i < badKept*3; i++ {
		b.WriteString("{oops\n")
	}
	fsys := fstest.MapFS{
		"mess-v1-mac-1.log": &fstest.MapFile{Data: []byte(b.String())},
	}

	got, err := Load(fsys, "mess-v1-*.log")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.BadTotal != badKept*3 {
		t.Errorf("BadTotal = %d, want %d", got.BadTotal, badKept*3)
	}
	if len(got.Bad) != badKept {
		t.Errorf("kept %d, want the cap of %d", len(got.Bad), badKept)
	}
}

// Events keep the name of the file they came from.
func TestLoadNamesTheFile(t *testing.T) {
	fsys := fstest.MapFS{
		"mess-v1-a.log": &fstest.MapFile{
			Data: []byte(`{"time":"2026-09-15T10:00:00Z","pid":1}` + "\n"),
		},
		"mess-v1-b.log": &fstest.MapFile{
			Data: []byte(`{"time":"2026-09-15T10:00:01Z","pid":2}` + "\n"),
		},
	}

	got, err := Load(fsys, "mess-v1-*.log")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(got.Files) != 2 || len(got.Events) != 2 {
		t.Fatalf("read %d files, %d events; want 2 and 2",
			len(got.Files), len(got.Events))
	}

	if got.Events[0].File != "mess-v1-a.log" || got.Events[1].File != "mess-v1-b.log" {
		t.Errorf("files = %q, %q; want mess-v1-a.log, mess-v1-b.log",
			got.Events[0].File, got.Events[1].File)
	}
}

// A bad glob is the read not happening, rather than an unreadable line.
func TestLoadStillFailsOnAnUnreadableFile(t *testing.T) {
	if _, err := Load(fstest.MapFS{}, "["); err == nil {
		t.Error("a bad glob should fail the load")
	}
}
