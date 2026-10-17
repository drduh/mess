package server

import (
	"io/fs"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

// length a request target is allowed to take in the log.
const logLine = 200

type logged struct {
	http.ResponseWriter
	status, bytes int
}

func (l *logged) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}

func (l *logged) Write(b []byte) (int, error) {
	if l.status == 0 {
		l.status = http.StatusOK
	}
	n, err := l.ResponseWriter.Write(b)
	l.bytes += n

	return n, err
}

func (s *Server) Handler(addr string) http.Handler {
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	mux.HandleFunc("GET /api/capture", s.handleCapture)
	mux.HandleFunc("POST /api/reload", s.handleReload)
	mux.HandleFunc("GET /api/report", s.handleReport)
	mux.HandleFunc("GET /api/timeline", s.handleTimeline)

	// Recover inside the log, outside everything else.
	return logRequests(recovering(s.ready(checkWindow(mux))))
}

// recovering answers a panic with 503.
func recovering(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}

			if v == http.ErrAbortHandler {
				panic(v)
			}

			log.Printf("panic serving %s %s: %v\n%s",
				forLog(r.Method), forLog(r.URL.RequestURI()), v, debug.Stack())

			if rec, ok := w.(*logged); ok && rec.status != 0 {
				return
			}
			http.Error(w, "the analysis could not be built for this request",
				http.StatusServiceUnavailable)
		}()

		next.ServeHTTP(w, r)
	})
}

func (s *Server) ready(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && s.current() == nil {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "reading the capture", http.StatusServiceUnavailable)
			return
		}

		next.ServeHTTP(w, r)
	})
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
