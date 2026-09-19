// Command mess reads macOS events captured by eslogger.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/drduh/mess/internal/config"
	"github.com/drduh/mess/internal/event"
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

	fmt.Printf("mess: started %s\n", time.Now().Format(server.StampLayout))

	root, err := os.OpenRoot(cfg.Dir)
	if err != nil {
		return err
	}
	defer root.Close()

	if cfg.Serve != "" {
		return server.Listen(cfg.Serve, cfg.Dir, root.FS(), cfg.Pattern, cfg.ErrLog)
	}

	loaded, err := event.Load(root.FS(), cfg.Pattern)
	if err != nil {
		return err
	}
	fmt.Printf("loaded %d events from %d files\n", len(loaded.Events), len(loaded.Files))

	return nil
}
