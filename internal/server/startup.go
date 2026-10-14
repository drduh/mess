package server

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// stamped prefixes each log line with a timestamp
type stamped struct{ w io.Writer }

// StampLayout is the display format: "%A %b %e %H:%M:%S"
const StampLayout = "Monday Jan _2 15:04:05"

func (s stamped) Write(p []byte) (int, error) {
	if _, err := io.WriteString(s.w, time.Now().Format(StampLayout)+" "); err != nil {
		return 0, err
	}

	return s.w.Write(p)
}

func Listen(addr string, dir string, fsys fs.FS, pattern, errLog string) error {
	log.SetFlags(0)
	log.SetOutput(stamped{os.Stderr})

	s := &Server{fsys: fsys, pattern: pattern, errLog: errLog, onRead: func(name string) {
		fmt.Printf("mess: reading %s\n", filepath.Join(dir, name))
	}}

	start := time.Now()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           s.Handler(addr),
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Printf("serving on http://%s\n", addr)
	if !loopback(addr) {
		fmt.Printf("warning: %s is not loopback!", addr)
	}

	serving := make(chan error, 1)
	go func() { serving <- srv.Serve(ln) }()

	if err := s.Reload(); err != nil {
		_ = srv.Close()
		return err
	}

	s.onRead = nil

	report(os.Stdout, s.current(), time.Since(start))

	return <-serving
}

// report says: which files were loaded, how many events each,
// and the period of time they cover.
func report(w io.Writer, snap *snapshot, took time.Duration) {
	type file struct {
		n           int
		first, last time.Time
	}

	var first, last time.Time
	per := map[string]*file{}
	uids := map[uint32]bool{}

	for _, e := range snap.loaded.Events {
		f := per[e.File]
		if f == nil {
			f = &file{first: e.Time, last: e.Time}
			per[e.File] = f
		}
		f.n++
		if e.Time.Before(f.first) {
			f.first = e.Time
		}
		if e.Time.After(f.last) {
			f.last = e.Time
		}
		if first.IsZero() || e.Time.Before(first) {
			first = e.Time
		}
		if e.Time.After(last) {
			last = e.Time
		}
		uids[e.UID] = true
	}

	const stamp = "2006-01-02 15:04:05"
	for _, name := range snap.loaded.Files {
		f := per[name]
		if f == nil {
			fmt.Fprintf(w, "  %-40s %8s  empty\n", name, "0")
			continue
		}

		fmt.Fprintf(w, "  %-40s %8d  %s to %s\n",
			name, f.n, f.first.Format(stamp), f.last.Format(stamp))
	}

	if len(snap.loaded.Files) == 0 {
		fmt.Fprintf(w, "  no files matched\n")
	}

	if snap.loaded.BadTotal > 0 {
		fmt.Fprintf(w, "mess: skipped %s that did not decode\n",
			plural(snap.loaded.BadTotal, "line"))
		for _, b := range snap.loaded.Bad {
			fmt.Fprintf(w, "  %s:%d  %s\n", b.File, b.Line, b.Why)
		}
		if snap.loaded.BadTotal > len(snap.loaded.Bad) {
			fmt.Fprintf(w, "  and %d more\n", snap.loaded.BadTotal-len(snap.loaded.Bad))
		}
	}

	fmt.Fprintf(w, "mess: %d events from %s in %s\n",
		len(snap.loaded.Events), plural(len(snap.loaded.Files), "file"),
		took.Round(time.Millisecond))

	if !first.IsZero() {
		fmt.Fprintf(w, "mess: covering %s, %s, %s\n",
			last.Sub(first).Round(time.Second),
			plural(len(uids), "account"),
			plural(len(snap.view(0).graph.Nodes), "binary"))
	}
}

// plural is a count with its noun.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}

	if noun == "binary" {
		return fmt.Sprintf("%d binaries", n)
	}

	return fmt.Sprintf("%d %ss", n, noun)
}

// loopback returns true when addr is reachable only from this machine.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	if host == "" {
		return false
	}

	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}
