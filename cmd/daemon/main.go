package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mayjain/aegis/internal/daemon"
)

func main() {
	socketPath := flag.String("socket", "/tmp/aegis.sock", "Unix socket path")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	d := daemon.New(*socketPath, logger)
	if err := d.Run(ctx); err != nil {
		logger.Error("daemon failed", "error", err)
		os.Exit(1)
	}
}
