// Package processing reports on loaded exec events.
package processing

import (
	"time"

	"github.com/drduh/mess/internal/classify"
	"github.com/drduh/mess/internal/pids"
	"github.com/drduh/mess/internal/signals"
	"github.com/drduh/mess/internal/tally"
)

type Report struct {
	Total int       `json:"total"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`

	Images  []Count `json:"images"`  // launched binary: its path or argv[0]
	Callers []Count `json:"callers"` // binary that called exec
	Lineage []Count `json:"lineage"` // caller to image pairs

	UniqueImages  int `json:"uniqueImages"`
	UniqueCallers int `json:"uniqueCallers"`

	ThirdParty      []Count `json:"thirdParty"` // signing ids where sys is false
	ThirdPartyTotal int     `json:"thirdPartyTotal"`

	Unsigned      []Count `json:"unsigned"` // callers with no team id and sys false
	UnsignedTotal int     `json:"unsignedTotal"`

	RootThird      []Count `json:"rootThird"` // non-platform callers running as uid 0
	RootThirdTotal int     `json:"rootThirdTotal"`

	UIDs  []Count `json:"uids"`
	Tools []Count `json:"tools"` // interpreters and other notable command names

	Signals []signals.Signal `json:"signals"`

	OnceCalls int `json:"onceCalls"` // callers seen exactly once

	MultiPath []Count `json:"multiPath"` // signing ids observed at more than one path

	Archs              []Count `json:"archs"`
	Translated         int     `json:"translated"`         // launches of an x86_64 image
	TranslatedBinaries int     `json:"translatedBinaries"` // distinct binaries behind them
	Architected        int     `json:"architected"`        // launches with recorded cpu type

	TranslatedTop []Count `json:"translatedTop"`
}

var tools = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"python": true, "python3": true, "perl": true, "ruby": true,
	"osascript": true, "swift": true, "node": true,
	"curl": true, "wget": true, "nc": true, "ssh": true, "scp": true,
	"base64": true, "xxd": true, "openssl": true,
	"launchctl": true, "defaults": true, "dscl": true, "security": true,
	"spctl": true, "csrutil": true, "tccutil": true, "sqlite3": true,
	"xattr": true, "codesign": true, "sudo": true,
}

// resolution of signal histogram
const signalBuckets = 120

// NamedIn lists signals that mention one binary.
func (r Report) NamedIn(name string) []string {
	return signals.NamedIn(r.Signals, name)
}

// Analyze walks the events once and builds a Report.
func Analyze(c pids.Capture) Report {
	events := c.Events
	r := Report{Total: len(events)}
	if len(events) == 0 {
		return r
	}

	images := tally.Counter{}
	callers := tally.Counter{}
	lineage := tally.Counter{}
	thirdParty := tally.Counter{}
	unsigned := tally.Counter{}
	rootThird := tally.Counter{}
	uids := tally.Counter{}
	toolUse := tally.Counter{}
	archs := tally.Counter{}
	translated := tally.Counter{}

	// signing id -> set of paths
	paths := map[string]map[string]bool{}
	seenAt := func(sign, path string) {
		if sign == "" || path == "" {
			return
		}

		if paths[sign] == nil {
			paths[sign] = map[string]bool{}
		}

		paths[sign][path] = true
	}

	r.First, r.Last = events[0].Time, events[0].Time

	names := newLabeller()
	for i := range events {
		e := &events[i]
		if e.Time.Before(r.First) {
			r.First = e.Time
		}
		if e.Time.After(r.Last) {
			r.Last = e.Time
		}

		img := e.Image()
		images.Add(img)
		callers.Add(e.Path)
		lineage.Add(names.lineage(e.Path, img))
		uids.Add(classify.UIDKey(e.UID))

		if !e.Sys {
			thirdParty.Add(names.caller(e))
			r.ThirdPartyTotal++

			if e.Team == "" {
				unsigned.Add(e.Path)
				r.UnsignedTotal++
			}

			if e.UID == 0 {
				rootThird.Add(names.caller(e))
				r.RootThirdTotal++
			}
		}

		if name := classify.Command(img); tools[name] {
			toolUse.Add(name)
		}

		if a := classify.Arch(e.CPU); a != "" {
			archs.Add(a)
			r.Architected++

			if a == classify.ArchX86_64 {
				r.Translated++
				translated.Add(classify.Command(img))
			}
		}

		seenAt(e.Sign, e.Path)
		seenAt(e.Target.Sign, e.Target.Path)
	}

	const topN = 10
	r.Archs = archs.Top(len(archs))
	r.Callers = callers.Top(topN)
	r.Images = images.Top(topN)
	r.Lineage = lineage.Top(topN)
	r.OnceCalls = len(callers.Once())
	r.RootThird = rootThird.Top(topN)
	r.ThirdParty = thirdParty.Top(topN)
	r.Tools = toolUse.Top(topN)
	r.TranslatedBinaries = len(translated)
	r.TranslatedTop = translated.Top(topN)
	r.UIDs = uids.Top(topN)
	r.UniqueCallers = len(callers)
	r.UniqueImages = len(images)
	r.Unsigned = unsigned.Top(topN)
	r.Signals = signals.Build(c, r.First, r.Last, signalBuckets)

	multi := []Count{}
	for sign, seen := range paths {
		if len(seen) > 1 {
			multi = append(multi, Count{Key: sign, N: len(seen)})
		}
	}
	r.MultiPath = tally.SortTop(multi, topN)

	return r
}

func signerLabel(sign, team string, sys bool) string {
	if sign == "" {
		sign = "(no signing id)"
	}
	switch {
	case sys:
		return sign + " [Apple]"
	case team == "":
		return sign + " [unsigned]"
	default:
		return sign + " [" + team + "]"
	}
}
