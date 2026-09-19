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

	s.onRead = nil

	return <-serving
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
