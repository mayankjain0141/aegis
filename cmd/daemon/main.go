package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mayjain/aegis/internal/daemon"
)

func main() {
	socketPath := flag.String("socket", "/tmp/aegis.sock", "Unix socket path")
	configPath := flag.String("config", "aegis.yaml", "Path to aegis.yaml config file")
	policyPath := flag.String("policies", "policies/default.yaml", "Path to policies YAML file")
	pgURL := flag.String("pg-url", "", "PostgreSQL connection URL (env: AEGIS_PG_URL)")
	flag.Parse()

	if *pgURL == "" {
		*pgURL = os.Getenv("AEGIS_PG_URL")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	d := daemon.NewWithOptions(*socketPath, *configPath, *policyPath, *pgURL, logger)

	if d.PGConnected() {
		fmt.Fprintf(os.Stderr, "aegis-daemon: PG connected\n")
	} else {
		fmt.Fprintf(os.Stderr, "aegis-daemon: running in no-PG mode (traces logged to stderr)\n")
	}

	if err := d.Run(ctx); err != nil {
		logger.Error("daemon failed", "error", err)
		os.Exit(1)
	}
}
