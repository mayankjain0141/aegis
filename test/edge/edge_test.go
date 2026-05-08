package edge_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mayjain/aegis/internal/daemon"
	"github.com/mayjain/aegis/internal/ipc"
)

const testSocket = "/tmp/aegis-edge-test.sock"

func startDaemon(t *testing.T) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	os.Remove(testSocket)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	d := daemon.NewWithPolicy(testSocket, "../e2e/testdata/aegis.yaml", "../e2e/testdata/policies.yaml", logger)

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

func TestConcurrentRequests_AllRoutedCorrectly(t *testing.T) {
	cancel, done := startDaemon(t)
	defer func() {
		cancel()
		<-done
	}()

	conn, shimID := connectAndRegister(t, "test-agent", "shell-mcp")
	defer conn.Close()

	const numRequests = 5
	type result struct {
		reqID string
		resp  *ipc.AegisEnvelope
		err   error
	}

	results := make([]result, numRequests)
	var wg sync.WaitGroup

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			c, sid := connectAndRegister(t, "test-agent", "shell-mcp")
			defer c.Close()

			reqID := uuid.New().String()
			env := &ipc.AegisEnvelope{
				Type:       "mcp_request",
				ShimID:     sid,
				AgentID:    "test-agent",
				ToolName:   "shell-mcp",
				RequestID:  reqID,
				MCPMessage: json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"echo hello"}},"id":` + `"` + reqID + `"` + `}`),
			}

			if err := ipc.WriteEnvelope(c, env); err != nil {
				results[idx] = result{reqID: reqID, err: err}
				return
			}

			resp, err := ipc.ReadEnvelope(c)
			results[idx] = result{reqID: reqID, resp: resp, err: err}
		}(i)
	}

	wg.Wait()
	_ = shimID

	for i, r := range results {
		if r.err != nil {
			t.Fatalf("request %d failed: %v", i, r.err)
		}
		if r.resp.Type != "mcp_response" {
			t.Fatalf("request %d: expected mcp_response, got %q (error: %s)", i, r.resp.Type, r.resp.Error)
		}
		if r.resp.RequestID != r.reqID {
			t.Fatalf("request %d: response request_id mismatch: got %q, want %q", i, r.resp.RequestID, r.reqID)
		}
	}
}

func TestRegistration_UnregisteredReject(t *testing.T) {
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
		ShimID:     "unregistered-shim-edge",
		AgentID:    "test-agent",
		ToolName:   "shell-mcp",
		RequestID:  "req-edge-123",
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

func TestPolicyPanic_FailsClosed(t *testing.T) {
	cancel, done := startDaemon(t)
	defer func() {
		cancel()
		<-done
	}()

	conn, shimID := connectAndRegister(t, "panic-agent", "shell-mcp")
	defer conn.Close()

	mcpReq := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"echo safe"}},"id":10}`
	env := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     shimID,
		AgentID:    "panic-agent",
		ToolName:   "shell-mcp",
		RequestID:  "req-panic-test",
		MCPMessage: json.RawMessage(mcpReq),
	}
	if err := ipc.WriteEnvelope(conn, env); err != nil {
		t.Fatalf("send mcp_request: %v", err)
	}

	resp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.Type != "mcp_response" {
		t.Fatalf("expected mcp_response, got %q (error: %s)", resp.Type, resp.Error)
	}

	respStr := string(resp.MCPMessage)
	if strings.Contains(respStr, "panic") {
		t.Fatalf("daemon exposed panic details to client: %s", respStr)
	}
}

func TestDenyResponse_IsError_NotJSONRPC(t *testing.T) {
	cancel, done := startDaemon(t)
	defer func() {
		cancel()
		<-done
	}()

	conn, shimID := connectAndRegister(t, "test-agent", "shell-mcp")
	defer conn.Close()

	mcpReq := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"rm -rf /"}},"id":99}`
	env := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     shimID,
		AgentID:    "test-agent",
		ToolName:   "shell-mcp",
		RequestID:  "req-deny-check",
		MCPMessage: json.RawMessage(mcpReq),
	}
	if err := ipc.WriteEnvelope(conn, env); err != nil {
		t.Fatalf("send mcp_request: %v", err)
	}

	resp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.Type != "mcp_response" {
		t.Fatalf("expected mcp_response, got %q (error: %s)", resp.Type, resp.Error)
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(resp.MCPMessage, &parsed); err != nil {
		t.Fatalf("unmarshal top-level: %v", err)
	}

	if _, hasError := parsed["error"]; hasError {
		t.Fatal("deny response uses JSON-RPC 'error' field; should use 'result' with isError=true")
	}

	var resultField struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(parsed["result"], &resultField); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if !resultField.IsError {
		t.Fatal("expected result.isError=true for denied call")
	}

	if len(resultField.Content) == 0 {
		t.Fatal("expected at least one content block in deny response")
	}
	if !strings.Contains(resultField.Content[0].Text, "Blocked") {
		t.Fatalf("expected 'Blocked' in deny text, got: %s", resultField.Content[0].Text)
	}
}
