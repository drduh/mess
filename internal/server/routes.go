package server

import (
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"
)

// length a request target is allowed to take in the log.
const logLine = 200

type logged struct {
	http.ResponseWriter
	status, bytes int
}

func (s *Server) Handler(addr string) http.Handler {
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.FS(static)))

	return logRequests(mux)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &logged{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		log.Printf("%s %s %d %dB %s",
			forLog(r.Method), forLog(r.URL.RequestURI()), rec.status, rec.bytes,
			time.Since(start).Round(time.Microsecond))
	})
}

func forLog(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > logLine {
		r := []rune(s)
		if len(r) > logLine {
			r = r[:logLine]
		}
		return string(r) + "..."
	}
	return s
}
