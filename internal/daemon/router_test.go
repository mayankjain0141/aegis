package daemon

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/internal/risk"
)

const testPolicyYAML = `version: "test-v1"
policies:
  - name: block-destructive-shell
    match:
      tool: shell_exec
      args_pattern: "(rm\\s+(-[a-z]*)?r[a-z]*f|DROP TABLE|shutdown|reboot|mkfs|dd if=)"
    action: deny
    severity: critical

  - name: default-allow
    match:
      tool: "*"
    action: allow
    severity: low
`

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testPolicyEvaluator(t *testing.T) policy.PolicyEvaluator {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-policy.yaml")
	if err := os.WriteFile(path, []byte(testPolicyYAML), 0644); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
	eval, err := policy.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load test policy: %v", err)
	}
	return eval
}

func testRiskScorer() *risk.CompositeScorer {
	return risk.NewCompositeScorer(
		[]risk.RiskSignal{
			risk.ToolClassificationSignal{},
			risk.ArgPatternSignal{},
			risk.RateSignal{},
		},
		map[string]float64{
			"tool_class":  1.0,
			"arg_pattern": 1.0,
			"rate":        1.0,
		},
	)
}

func testRouter(t *testing.T) *Router {
	tools := map[string]ToolConfig{
		"shell-mcp": {Command: "echo", Args: []string{"mock"}},
	}
	exec := NewExecutor(tools, testLogger())
	return NewRouter(exec, testPolicyEvaluator(t), testRiskScorer(), &Metrics{}, testLogger())
}

func TestRouter_Register(t *testing.T) {
	r := testRouter(t)
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
	r := testRouter(t)
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
	r := testRouter(t)
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
	r := testRouter(t)
	conn, _ := net.Pipe()
	defer conn.Close()

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
	r := testRouter(t)
	conn, _ := net.Pipe()
	defer conn.Close()

	regEnv := &ipc.AegisEnvelope{
		Type:     "register",
		ShimID:   "shim_001",
		AgentID:  "agent1",
		ToolName: "shell-mcp",
	}
	if _, err := r.HandleEnvelope(conn, regEnv); err != nil {
		t.Fatalf("register failed: %v", err)
	}

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
	if !strings.Contains(mcpResp.Result.Content[0].Text, "Blocked by Aegis") {
		t.Errorf("deny text = %q, expected 'Blocked by Aegis'", mcpResp.Result.Content[0].Text)
	}
	if string(mcpResp.ID) != "99" {
		t.Errorf("id = %s, want 99", mcpResp.ID)
	}
}

func TestRouter_MCPRequest_SafeAllowed(t *testing.T) {
	r := testRouter(t)
	conn, _ := net.Pipe()
	defer conn.Close()

	regEnv := &ipc.AegisEnvelope{
		Type:     "register",
		ShimID:   "shim_001",
		AgentID:  "agent1",
		ToolName: "shell-mcp",
	}
	if _, err := r.HandleEnvelope(conn, regEnv); err != nil {
		t.Fatalf("register failed: %v", err)
	}

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

func TestRouter_MCPRequest_RiskScoreComputed(t *testing.T) {
	r := testRouter(t)
	conn, _ := net.Pipe()
	defer conn.Close()

	regEnv := &ipc.AegisEnvelope{
		Type:     "register",
		ShimID:   "shim_001",
		AgentID:  "agent1",
		ToolName: "shell-mcp",
	}
	if _, err := r.HandleEnvelope(conn, regEnv); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	mcpMsg := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":10}`)
	reqEnv := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "shim_001",
		RequestID:  "req_risk",
		ToolName:   "shell-mcp",
		MCPMessage: mcpMsg,
	}

	_, err := r.HandleEnvelope(conn, reqEnv)
	if err != nil {
		t.Fatalf("HandleEnvelope failed: %v", err)
	}

	sess, ok := r.sessions.Get("shim_001")
	if !ok {
		t.Fatal("session not found")
	}
	ctx := sess.GetContext()
	if ctx.CallsLastMinute < 1 {
		t.Error("expected at least 1 call recorded")
	}
}

func TestRouter_Cancel(t *testing.T) {
	r := testRouter(t)
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
	r := testRouter(t)
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
