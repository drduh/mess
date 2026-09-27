package processing

import (
	"github.com/drduh/mess/internal/signals"

	"fmt"
	"io"
	"time"
)

const Stamp = "Monday Jan 2 15:04:05"

// Print writes the report as plain text.
func (r Report) Print(w io.Writer) {
	if r.Total == 0 {
		fmt.Fprintln(w, "no events")
		return
	}

	span := r.Last.Sub(r.First)
	fmt.Fprintf(w, "%s to %s (%s, %s events/hour)\n",
		r.First.Local().Format(Stamp),
		r.Last.Local().Format(Stamp),
		humanDur(span), perHour(r.Total, span))
	fmt.Fprintf(w, "%d unique images from %d unique callers\n",
		r.UniqueImages, r.UniqueCallers)

	section(w, "launched images", r.Images)
	section(w, "callers of exec", r.Callers)
	section(w, "caller -> image", r.Lineage)

	total(w, "non-platform callers", r.ThirdPartyTotal, r.Total, r.ThirdParty)
	total(w, "unsigned callers", r.UnsignedTotal, r.Total, r.Unsigned)
	total(w, "non-platform callers running as root", r.RootThirdTotal, r.Total, r.RootThird)

	section(w, "by uid", r.UIDs)
	section(w, "interpreters and notable tools", r.Tools)

	for _, sg := range r.Signals {
		if sg.Count == 0 || sg.Tier == "context" {
			continue
		}

		fmt.Fprintf(w, "\n%s: %s, %d events, %d distinct\n",
			sg.Tier, sg.Title, sg.Count, sg.Distinct)

		for _, row := range sg.Rows[:min(len(sg.Rows), 5)] {
			fmt.Fprintf(w, "  %6d  %s\n", row.N, row.Key)
		}
	}

	once := signals.ByID(r.Signals, "once")
	if once != nil {
		fmt.Fprintf(w, "\nrun once: %d of %d unique images, %d of %d unique callers\n",
			once.Distinct, r.UniqueImages, r.OnceCalls, r.UniqueCallers)
	}
}

func section(w io.Writer, title string, counts []Count) {
	fmt.Fprintf(w, "\n%s\n", title)
	rows(w, counts)
}

// total prints a heading carrying an event count and share of the run.
func total(w io.Writer, title string, n, all int, counts []Count) {
	fmt.Fprintf(w, "\n%s: %d events (%.1f%%)\n", title, n, pct(n, all))
	rows(w, counts)
}

func rows(w io.Writer, counts []Count) {
	if len(counts) == 0 {
		fmt.Fprintln(w, "  none")
		return
	}

	for _, c := range counts {
		fmt.Fprintf(w, "  %7d  %s\n", c.N, trunc(c.Key, 96))
	}
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}

	return float64(n) * 100 / float64(total)
}

// perHour formats an event rate.
func perHour(n int, d time.Duration) string {
	if d <= 0 {
		return "n/a"
	}

	rate := float64(n) / d.Hours()
	if rate >= 100 {
		return fmt.Sprintf("%.0f", rate)
	}

	return fmt.Sprintf("%.1f", rate)
}

// humanDur renders a span in days, hours and minutes.
func humanDur(d time.Duration) string {
	d = d.Round(time.Minute)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, h, m)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// PrintActivity draws the timeline as rows of block characters.
func PrintActivity(w io.Writer, t Timeline) {
	if t.Buckets == 0 {
		return
	}

	fmt.Fprintf(w, "\nactivity, %s per column\n", humanDur(
		time.Duration(t.Seconds*float64(time.Second))))
	fmt.Fprintf(w, "  %-22s %s\n", "all events", spark(t.Total, t.Peak))

	for _, row := range t.Rows {
		label := row.Name
		if row.Role != "" {
			label += " (" + row.Role + ")"
		}

		fmt.Fprintf(w, "  %-22s %s  %d\n", trunc(label, 22),
			spark(row.Counts, row.Peak), row.Total)
	}
}

// spark maps counts onto height blocks.
func spark(counts []int, peak int) string {
	blocks := []rune(" ▁▂▃▄▅▆▇█")

	if peak < 1 {
		peak = 1
	}

	out := make([]rune, len(counts))

	for i, c := range counts {
		if c == 0 {
			out[i] = blocks[0]
			continue
		}

		step := 1 + (c*(len(blocks)-2))/peak
		if step > len(blocks)-1 {
			step = len(blocks) - 1
		}

		out[i] = blocks[step]
	}

	return string(out)
}
