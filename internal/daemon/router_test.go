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

func testRouter() *Router {
	tools := map[string]ToolConfig{
		"shell-mcp": {Command: "echo", Args: []string{"mock"}},
	}
	exec := NewExecutor(tools, testLogger())
	return NewRouter(exec, testLogger())
}

func TestRouter_Register(t *testing.T) {
	r := testRouter()
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
	r := testRouter()
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
	r := testRouter()
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
	r := testRouter()
	conn, _ := net.Pipe()
	defer conn.Close()

	// Register first
	regEnv := &ipc.AegisEnvelope{
		Type:     "register",
		ShimID:   "shim_001",
		AgentID:  "agent1",
		ToolName: "shell-mcp",
	}
	_, err := r.HandleEnvelope(conn, regEnv)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Send MCP request
	mcpMsg := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":42}`)
	reqEnv := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "shim_001",
		RequestID:  "req_1",
		ToolName:   "shell-mcp",
		MCPMessage: mcpMsg,
	}

	resp, err := r.HandleEnvelope(conn, reqEnv)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}

	if resp.Type != "mcp_response" {
		t.Errorf("Type = %q, want %q", resp.Type, "mcp_response")
	}

	var mcpResp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.MCPMessage, &mcpResp); err != nil {
		t.Fatalf("unmarshal MCP response: %v", err)
	}
	if len(mcpResp.Result.Content) == 0 {
		t.Fatal("expected content in response")
	}
	if mcpResp.Result.Content[0].Text != "[mock] tool executed successfully" {
		t.Errorf("text = %q, want mock response", mcpResp.Result.Content[0].Text)
	}
}

func TestRouter_MCPRequest_DangerousBlocked(t *testing.T) {
	r := testRouter()
	conn, _ := net.Pipe()
	defer conn.Close()

	// Register
	regEnv := &ipc.AegisEnvelope{
		Type:     "register",
		ShimID:   "shim_001",
		AgentID:  "agent1",
		ToolName: "shell-mcp",
	}
	if _, err := r.HandleEnvelope(conn, regEnv); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Send dangerous MCP request with "rm -rf" in arguments
	mcpMsg := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"rm -rf /"}},"id":99}`)
	reqEnv := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "shim_001",
		RequestID:  "req_danger",
		ToolName:   "shell-mcp",
		MCPMessage: mcpMsg,
	}

	resp, err := r.HandleEnvelope(conn, reqEnv)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}

	if resp.Type != "mcp_response" {
		t.Errorf("Type = %q, want %q", resp.Type, "mcp_response")
	}

	var mcpResp struct {
		JSONRPC string `json:"jsonrpc"`
		Result  struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(resp.MCPMessage, &mcpResp); err != nil {
		t.Fatalf("unmarshal blocked response: %v", err)
	}

	if !mcpResp.Result.IsError {
		t.Error("expected isError=true for blocked request")
	}
	if len(mcpResp.Result.Content) == 0 {
		t.Fatal("expected content in deny response")
	}
	if mcpResp.Result.Content[0].Text != "Blocked by Aegis: dangerous pattern 'rm -rf' detected" {
		t.Errorf("deny text = %q", mcpResp.Result.Content[0].Text)
	}
	if string(mcpResp.ID) != "99" {
		t.Errorf("id = %s, want 99", mcpResp.ID)
	}
}

func TestRouter_MCPRequest_SafeAllowed(t *testing.T) {
	r := testRouter()
	conn, _ := net.Pipe()
	defer conn.Close()

	// Register
	regEnv := &ipc.AegisEnvelope{
		Type:     "register",
		ShimID:   "shim_001",
		AgentID:  "agent1",
		ToolName: "shell-mcp",
	}
	if _, err := r.HandleEnvelope(conn, regEnv); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Send safe MCP request
	mcpMsg := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls -la"}},"id":7}`)
	reqEnv := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "shim_001",
		RequestID:  "req_safe",
		ToolName:   "shell-mcp",
		MCPMessage: mcpMsg,
	}

	resp, err := r.HandleEnvelope(conn, reqEnv)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}

	if resp.Type != "mcp_response" {
		t.Errorf("Type = %q, want %q", resp.Type, "mcp_response")
	}

	var mcpResp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.MCPMessage, &mcpResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if mcpResp.Result.IsError {
		t.Error("safe command should NOT be blocked")
	}
	if len(mcpResp.Result.Content) == 0 {
		t.Fatal("expected content in response")
	}
	if mcpResp.Result.Content[0].Text != "[mock] tool executed successfully" {
		t.Errorf("text = %q, want mock success", mcpResp.Result.Content[0].Text)
	}
}

func TestRouter_Cancel(t *testing.T) {
	r := testRouter()
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
	r := testRouter()
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
