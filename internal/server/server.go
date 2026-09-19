// Package server provides the HTTP application.
package server

import (
	"io/fs"
	"sync"
)

type Server struct {
	onRead  func(name string)
	fsys    fs.FS
	pattern string
	errLog  string

	mu sync.RWMutex
}
