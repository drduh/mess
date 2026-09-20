package event

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

type Loaded struct {
	Events   []Event
	Files    []string  // names read, in glob order
	Bad      []BadLine // lines which did not decode
	BadTotal int       // how many there were in all
}

type BadLine struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Why  string `json:"why"`
	Text string `json:"text"`
}

// how many bad lines are held
const badKept = 20

// how much of an unreadable line is worth keeping
const badText = 120

// Load reads every file in fsys matching pattern and returns the
// events they contain, in file name order.
func Load(fsys fs.FS, pattern string) (Loaded, error) {
	return LoadEach(fsys, pattern, nil)
}

func LoadEach(fsys fs.FS, pattern string, each func(name string)) (Loaded, error) {
	names, err := fs.Glob(fsys, pattern)
	if err != nil {
		return Loaded{}, fmt.Errorf("glob %q: %w", pattern, err)
	}

	out := Loaded{Files: names}
	for _, name := range names {
		if each != nil {
			each(name)
		}
		if err := loadFile(fsys, name, &out); err != nil {
			return Loaded{}, err
		}
	}
	return out, nil
}

func loadFile(fsys fs.FS, name string, out *Loaded) error {
	f, err := fsys.Open(name)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for n := 1; ; n++ {
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read %s: %w", name, err)
		}
		done := errors.Is(err, io.EOF)
		if text := strings.TrimSpace(line); text != "" {
			var e Event
			if err := json.Unmarshal([]byte(text), &e); err != nil {
				out.note(name, n, err, text)
			} else {
				e.File = name
				out.Events = append(out.Events, e)
			}
		}
		if done {
			return nil
		}
	}
}

// note records a line that did not decode.
func (l *Loaded) note(name string, line int, why error, text string) {
	l.BadTotal++
	if len(l.Bad) >= badKept {
		return
	}
	if len(text) > badText {
		text = text[:badText] + "..."
	}
	l.Bad = append(l.Bad, BadLine{File: name, Line: line, Why: why.Error(), Text: text})
}
