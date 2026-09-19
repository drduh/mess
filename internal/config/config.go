// Package config holds the runtime settings for the monitor.
package config

import (
	"flag"
	"fmt"
	"os"
	"runtime"
)

// Config is the set of runtime settings.
type Config struct {
	Dir     string // directory holding the eslogger logs
	Pattern string // glob matched against file names in Dir
	Serve   string // listen address for the web interface, empty to print
	ErrLog  string // filter error output in Dir, empty to skip
}

var Version string

func Describe() string {
	return "mess v1, " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
}

// Parse builds a Config from the command line flags.
func Parse() Config {
	var c Config

	flag.StringVar(&c.Dir, "dir", "/var/log/mess",
		"directory to read eslogger logs from")
	flag.StringVar(&c.Pattern, "pattern", "mess-v1-*.log",
		"glob for log file names within -dir")
	flag.StringVar(&c.Serve, "serve", "127.0.0.1:8080",
		"listen address for web interface, such as localhost:8080")
	flag.StringVar(&c.ErrLog, "errlog", "filterErr.log",
		"filter error output, a file within -dir; empty to skip")

	version := flag.Bool("version", false, "print the build and exit")
	flag.Parse()
	if *version {
		fmt.Println(Describe())
		os.Exit(0)
	}

	return c
}
