// Command mess reads macOS events captured by eslogger.
package main

import (
	"fmt"
	"os"

	"github.com/drduh/mess/internal/config"
	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/processing"
	"github.com/drduh/mess/internal/server"
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

	if cfg.Serve != "" {
		return server.Listen(cfg.Serve, root.FS(), cfg.Pattern)
	}

	loaded, err := event.Load(root.FS(), cfg.Pattern)
	if err != nil {
		return err
	}
	fmt.Printf("loaded %d events from %d files\n",
		len(loaded.Events), len(loaded.Files))

	processing.Analyze(loaded.Events).Print(os.Stdout)
	processing.PrintActivity(
		os.Stdout, processing.BuildTimeline(loaded.Events, 60, 10, nil))

	return nil
}
