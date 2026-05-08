package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
)

func TestExecute_ReturnsResult(t *testing.T) {
	tools := map[string]ToolConfig{
		"shell-mcp": {Command: "echo", Args: []string{"hello"}},
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	exec := NewExecutor(tools, logger)

	mcpMsg := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":42}`)

	result, err := exec.Execute(context.Background(), "shell-mcp", mcpMsg)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		Result  struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want %q", resp.JSONRPC, "2.0")
	}
	if len(resp.Result.Content) != 1 {
		t.Fatalf("content length = %d, want 1", len(resp.Result.Content))
	}
	if resp.Result.Content[0].Text != "[mock] tool executed successfully" {
		t.Errorf("text = %q, want %q", resp.Result.Content[0].Text, "[mock] tool executed successfully")
	}
	if string(resp.ID) != "42" {
		t.Errorf("id = %s, want 42", resp.ID)
	}
}

func TestExecute_UnknownTool_ReturnsError(t *testing.T) {
	tools := map[string]ToolConfig{
		"shell-mcp": {Command: "echo", Args: []string{"hello"}},
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	exec := NewExecutor(tools, logger)

	mcpMsg := json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"unknown"},"id":1}`)

	_, err := exec.Execute(context.Background(), "nonexistent-tool", mcpMsg)
	if err == nil {
		t.Fatal("expected error for unknown tool, got nil")
	}
	if err.Error() != `unknown tool: "nonexistent-tool"` {
		t.Errorf("error = %q, want %q", err.Error(), `unknown tool: "nonexistent-tool"`)
	}
}
