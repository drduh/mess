// Command mess reads macOS events captured by eslogger.
package main

import (
	"fmt"
	"os"

	"github.com/drduh/mess/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mess:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.Parse()

	root, err := os.OpenRoot(cfg.Dir)
	if err != nil {
		return err
	}
	defer root.Close()

	return nil
}
