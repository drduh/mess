// Package config holds the runtime settings for the monitor.
package config

import "flag"

// Config is the set of runtime settings.
type Config struct {
	Dir     string // directory holding the eslogger logs
	Pattern string // glob matched against file names in Dir
	Serve   string // listen address for the web interface, empty to print
}

// Parse builds a Config from the command line flags.
func Parse() Config {
	var c Config
	flag.StringVar(&c.Dir, "dir", ".", "directory to read eslogger logs from")
	flag.StringVar(&c.Pattern, "pattern", "exec-*.log", "glob for log file names within -dir")
	flag.StringVar(&c.Serve, "serve", "", "listen address for the web interface, such as localhost:8080")
	flag.Parse()
	return c
}
