package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

// ToolConfig holds the command to execute for a tool.
type ToolConfig struct {
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	Env     map[string]string `yaml:"env,omitempty"`
}

// Executor handles tool call execution.
type Executor struct {
	tools  map[string]ToolConfig
	logger *slog.Logger
}

func NewExecutor(tools map[string]ToolConfig, logger *slog.Logger) *Executor {
	return &Executor{
		tools:  tools,
		logger: logger,
	}
}

// Execute runs a tool call. For Phase 1, returns a mock response since we don't
// have real MCP tool servers yet. The MCP request ID is preserved in the response.
func (e *Executor) Execute(ctx context.Context, toolName string, mcpMessage json.RawMessage) (json.RawMessage, error) {
	if _, ok := e.tools[toolName]; !ok {
		return nil, fmt.Errorf("unknown tool: %q", toolName)
	}

	e.logger.Info("executing tool", "tool", toolName)

	var req struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(mcpMessage, &req); err != nil {
		return nil, fmt.Errorf("parse MCP message: %w", err)
	}

	resp := map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": "[mock] tool executed successfully"},
			},
		},
		"id": req.ID,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return data, nil
}
