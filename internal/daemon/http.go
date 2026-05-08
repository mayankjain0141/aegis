package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/mayjain/aegis/internal/ws"
)

// Metrics holds simple counters for the HTTP /metrics endpoint.
type Metrics struct {
	TracesWritten atomic.Int64
	TracesDropped atomic.Int64
	CallsTotal    atomic.Int64
	DeniedTotal   atomic.Int64
}

func (d *Daemon) startHTTP(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", d.handleHealth)
	mux.HandleFunc("GET /metrics", d.handleMetrics)
	mux.HandleFunc("GET /ws", d.handleWS)

	d.httpServer = &http.Server{
		Handler:     mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("http listen %s: %w", addr, err)
	}
	d.logger.Info("http server started", "addr", addr)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d.httpServer.Shutdown(shutCtx)
	}()

	go func() {
		if err := d.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			d.logger.Error("http server error", "error", err)
		}
	}()

	return nil
}

func (d *Daemon) handleHealth(w http.ResponseWriter, r *http.Request) {
	uptime := int(time.Since(d.startTime).Seconds())
	activeSessions := d.router.Sessions().Count()

	resp := map[string]any{
		"status":          "ok",
		"uptime_s":        uptime,
		"pg_connected":    d.PGConnected(),
		"active_sessions": activeSessions,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (d *Daemon) handleMetrics(w http.ResponseWriter, r *http.Request) {
	written, dropped := d.collector.Stats()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "# HELP traces_written Total trace events written\n")
	fmt.Fprintf(w, "# TYPE traces_written counter\n")
	fmt.Fprintf(w, "traces_written %d\n", written)
	fmt.Fprintf(w, "# HELP traces_dropped Total trace events dropped\n")
	fmt.Fprintf(w, "# TYPE traces_dropped counter\n")
	fmt.Fprintf(w, "traces_dropped %d\n", dropped)
	fmt.Fprintf(w, "# HELP calls_total Total tool calls processed\n")
	fmt.Fprintf(w, "# TYPE calls_total counter\n")
	fmt.Fprintf(w, "calls_total %d\n", d.metrics.CallsTotal.Load())
	fmt.Fprintf(w, "# HELP denied_total Total tool calls denied\n")
	fmt.Fprintf(w, "# TYPE denied_total counter\n")
	fmt.Fprintf(w, "denied_total %d\n", d.metrics.DeniedTotal.Load())
	fmt.Fprintf(w, "# HELP ws_clients_active Active WebSocket clients\n")
	fmt.Fprintf(w, "# TYPE ws_clients_active gauge\n")
	fmt.Fprintf(w, "ws_clients_active %d\n", d.hub.ClientCount())
}

func (d *Daemon) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		d.logger.Error("ws accept failed", "error", err)
		return
	}

	client := ws.NewClient(d.hub, conn)
	client.SetMessageHandler(d.handleWSMessage)
	client.Serve(r.Context())
}

// BroadcastEvent serializes and broadcasts a trace event to connected WS clients.
func (d *Daemon) BroadcastEvent(data []byte) {
	if d.hub != nil {
		d.hub.Broadcast(data)
	}
}

// Hub returns the WebSocket hub for external use.
func (d *Daemon) Hub() *ws.Hub {
	return d.hub
}

// handleWSMessage processes incoming WebSocket messages (approval responses).
func (d *Daemon) handleWSMessage(data []byte) {
	var msg struct {
		Type string `json:"type"`
		Data struct {
			ApprovalID string `json:"approval_id"`
			Reason     string `json:"reason"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		d.logger.Warn("invalid ws message", "error", err)
		return
	}

	gate := d.router.ApprovalGate()
	if gate == nil {
		d.logger.Warn("received approval message but no gate configured")
		return
	}

	switch msg.Type {
	case "approve":
		if err := gate.Resolve(msg.Data.ApprovalID, "approve", msg.Data.Reason); err != nil {
			d.logger.Warn("approval resolve failed", "error", err, "id", msg.Data.ApprovalID)
		}
	case "deny":
		if err := gate.Resolve(msg.Data.ApprovalID, "deny", msg.Data.Reason); err != nil {
			d.logger.Warn("denial resolve failed", "error", err, "id", msg.Data.ApprovalID)
		}
	default:
		d.logger.Debug("unhandled ws message type", "type", msg.Type)
	}
}

// LoggerForTest exports the logger for testing.
func (d *Daemon) Logger() *slog.Logger {
	return d.logger
}
