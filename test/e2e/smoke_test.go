package e2e_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mayjain/aegis/internal/daemon"
	"github.com/mayjain/aegis/internal/ipc"
)

const testSocket = "/tmp/aegis-test.sock"

func startDaemon(t *testing.T) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	os.Remove(testSocket)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	d := daemon.NewWithPolicy(testSocket, "testdata/aegis.yaml", "testdata/policies.yaml", logger)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		_ = d.Run(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", testSocket)
		if err == nil {
			conn.Close()
			return cancel, done
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("daemon did not start within 2s")
	return nil, nil
}

func connectAndRegister(t *testing.T, agentID, toolName string) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("unix", testSocket)
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}

	shimID := uuid.New().String()
	regEnv := &ipc.AegisEnvelope{
		Type:     "register",
		ShimID:   shimID,
		AgentID:  agentID,
		ToolName: toolName,
	}
	if err := ipc.WriteEnvelope(conn, regEnv); err != nil {
		conn.Close()
		t.Fatalf("send register: %v", err)
	}

	resp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("read register response: %v", err)
	}
	if resp.Type != "registered" {
		conn.Close()
		t.Fatalf("expected 'registered', got %q (error: %s)", resp.Type, resp.Error)
	}

	return conn, shimID
}

func sendMCPRequest(t *testing.T, conn net.Conn, shimID, toolName, mcpJSON string) *ipc.AegisEnvelope {
	t.Helper()
	reqID := uuid.New().String()

	env := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     shimID,
		AgentID:    "test-agent",
		ToolName:   toolName,
		RequestID:  reqID,
		MCPMessage: json.RawMessage(mcpJSON),
	}
	if err := ipc.WriteEnvelope(conn, env); err != nil {
		t.Fatalf("send mcp_request: %v", err)
	}

	resp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		t.Fatalf("read mcp_response: %v", err)
	}
	return resp
}

func TestSmoke_ToolCallPassesThrough(t *testing.T) {
	cancel, done := startDaemon(t)
	defer func() {
		cancel()
		<-done
	}()

	conn, shimID := connectAndRegister(t, "test-agent", "shell-mcp")
	defer conn.Close()

	mcpReq := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":1}`
	resp := sendMCPRequest(t, conn, shimID, "shell-mcp", mcpReq)

	if resp.Type != "mcp_response" {
		t.Fatalf("expected mcp_response, got %q (error: %s)", resp.Type, resp.Error)
	}

	respStr := string(resp.MCPMessage)
	if !strings.Contains(respStr, "tool executed successfully") {
		t.Fatalf("expected mock success response, got: %s", respStr)
	}
}

func TestSmoke_BlockedCallReturnsIsError(t *testing.T) {
	cancel, done := startDaemon(t)
	defer func() {
		cancel()
		<-done
	}()

	conn, shimID := connectAndRegister(t, "test-agent", "shell-mcp")
	defer conn.Close()

	mcpReq := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"rm -rf /"}},"id":2}`
	resp := sendMCPRequest(t, conn, shimID, "shell-mcp", mcpReq)

	if resp.Type != "mcp_response" {
		t.Fatalf("expected mcp_response, got %q (error: %s)", resp.Type, resp.Error)
	}

	var parsed struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.MCPMessage, &parsed); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if !parsed.Result.IsError {
		t.Fatal("expected isError=true for blocked call")
	}

	if len(parsed.Result.Content) == 0 || !strings.Contains(parsed.Result.Content[0].Text, "Blocked") {
		t.Fatalf("expected 'Blocked' in response text, got: %v", parsed.Result.Content)
	}
}

func TestSmoke_UnregisteredShimRejected(t *testing.T) {
	cancel, done := startDaemon(t)
	defer func() {
		cancel()
		<-done
	}()

	conn, err := net.Dial("unix", testSocket)
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer conn.Close()

	env := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "unregistered-shim",
		AgentID:    "test-agent",
		ToolName:   "shell-mcp",
		RequestID:  "req-123",
		MCPMessage: json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":3}`),
	}
	if err := ipc.WriteEnvelope(conn, env); err != nil {
		t.Fatalf("send mcp_request: %v", err)
	}

	resp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.Type != "error" {
		t.Fatalf("expected error response, got type=%q", resp.Type)
	}
	if !strings.Contains(resp.Error, "not registered") {
		t.Fatalf("expected 'not registered' error, got: %s", resp.Error)
	}
}
