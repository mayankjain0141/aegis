package daemon

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/mayjain/aegis/internal/ipc"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRouter_Register(t *testing.T) {
	r := NewRouter(testLogger())
	conn, _ := net.Pipe()
	defer conn.Close()

	env := &ipc.AegisEnvelope{
		Type:    "register",
		ShimID:  "shim_001",
		AgentID: "claude-main",
	}

	resp, err := r.HandleEnvelope(conn, env)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}

	if resp.Type != "registered" {
		t.Errorf("Type = %q, want %q", resp.Type, "registered")
	}
	if resp.SessionID == "" {
		t.Error("SessionID should be set")
	}
	if resp.ShimID != "shim_001" {
		t.Errorf("ShimID = %q, want %q", resp.ShimID, "shim_001")
	}

	if r.sessions.Count() != 1 {
		t.Errorf("sessions.Count() = %d, want 1", r.sessions.Count())
	}
}

func TestRouter_Register_MissingShimID(t *testing.T) {
	r := NewRouter(testLogger())
	conn, _ := net.Pipe()
	defer conn.Close()

	env := &ipc.AegisEnvelope{
		Type: "register",
	}

	resp, err := r.HandleEnvelope(conn, env)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}
	if resp.Type != "error" {
		t.Errorf("Type = %q, want %q", resp.Type, "error")
	}
	if resp.Error == "" {
		t.Error("Error message should be set")
	}
}

func TestRouter_UnregisteredReject(t *testing.T) {
	r := NewRouter(testLogger())
	conn, _ := net.Pipe()
	defer conn.Close()

	env := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "unknown_shim",
		MCPMessage: json.RawMessage(`{"id":1}`),
	}

	resp, err := r.HandleEnvelope(conn, env)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}

	if resp.Type != "error" {
		t.Errorf("Type = %q, want %q", resp.Type, "error")
	}
	if resp.Error == "" {
		t.Error("Error should explain the rejection")
	}
}

func TestRouter_MCPRequest(t *testing.T) {
	r := NewRouter(testLogger())
	conn, _ := net.Pipe()
	defer conn.Close()

	// Register first
	regEnv := &ipc.AegisEnvelope{
		Type:    "register",
		ShimID:  "shim_001",
		AgentID: "agent1",
	}
	_, err := r.HandleEnvelope(conn, regEnv)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Send MCP request
	mcpMsg := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell"},"id":42}`)
	reqEnv := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "shim_001",
		RequestID:  "req_1",
		MCPMessage: mcpMsg,
	}

	resp, err := r.HandleEnvelope(conn, reqEnv)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}

	if resp.Type != "mcp_response" {
		t.Errorf("Type = %q, want %q", resp.Type, "mcp_response")
	}
	if string(resp.MCPMessage) != string(mcpMsg) {
		t.Errorf("MCPMessage = %s, want %s", resp.MCPMessage, mcpMsg)
	}
}

func TestRouter_Cancel(t *testing.T) {
	r := NewRouter(testLogger())
	conn, _ := net.Pipe()
	defer conn.Close()

	env := &ipc.AegisEnvelope{
		Type:      "cancel",
		ShimID:    "shim_001",
		RequestID: "req_1",
	}

	resp, err := r.HandleEnvelope(conn, env)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}
	if resp.Type != "cancelled" {
		t.Errorf("Type = %q, want %q", resp.Type, "cancelled")
	}
}

func TestRouter_UnknownType(t *testing.T) {
	r := NewRouter(testLogger())
	conn, _ := net.Pipe()
	defer conn.Close()

	env := &ipc.AegisEnvelope{
		Type:   "bogus",
		ShimID: "shim_001",
	}

	resp, err := r.HandleEnvelope(conn, env)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}
	if resp.Type != "error" {
		t.Errorf("Type = %q, want %q", resp.Type, "error")
	}
	if resp.Error == "" {
		t.Error("Error message should be set for unknown type")
	}
}
