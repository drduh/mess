// Package server provides the HTTP application.
package server

import (
	"embed"
	"io/fs"
	"sync"
)

//go:embed static/*.html
var assets embed.FS

type Server struct {
	onRead func(name string)
	fsys   fs.FS

	pattern string
	errLog  string

	mu sync.RWMutex
}
