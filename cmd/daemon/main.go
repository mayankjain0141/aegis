package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/mayjain/aegis/internal/ipc"
)

const socketPath = "/tmp/aegis.sock"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Remove stale socket
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		slog.Error("failed to listen", "path", socketPath, "error", err)
		os.Exit(1)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	slog.Info("daemon started", "socket", socketPath, "mode", "echo")

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigCh
		slog.Info("shutting down")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed (shutdown)
			break
		}
		go handleConnection(conn)
	}

	fmt.Fprintln(os.Stderr, "daemon stopped")
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	slog.Info("connection accepted")

	for {
		env, err := ipc.ReadEnvelope(conn)
		if err != nil {
			slog.Debug("connection closed", "error", err)
			return
		}

		slog.Info("received envelope", "type", env.Type, "shim_id", env.ShimID, "tool", env.ToolName)

		// Echo mode: send it right back
		env.Type = "mcp_response"
		if err := ipc.WriteEnvelope(conn, env); err != nil {
			slog.Error("write failed", "error", err)
			return
		}
	}
}
