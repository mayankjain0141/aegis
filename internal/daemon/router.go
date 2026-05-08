package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/session"
)

// Router handles incoming envelopes and dispatches them.
type Router struct {
	sessions *session.Registry
	executor *Executor
	logger   *slog.Logger
}

func NewRouter(executor *Executor, logger *slog.Logger) *Router {
	return &Router{
		sessions: session.NewRegistry(),
		executor: executor,
		logger:   logger,
	}
}

func (r *Router) Sessions() *session.Registry {
	return r.sessions
}

func (r *Router) HandleEnvelope(conn net.Conn, env *ipc.AegisEnvelope) (*ipc.AegisEnvelope, error) {
	switch env.Type {
	case "register":
		return r.handleRegister(env)
	case "mcp_request":
		return r.handleMCPRequest(env)
	case "cancel":
		return r.handleCancel(env)
	default:
		return &ipc.AegisEnvelope{
			Type:   "error",
			ShimID: env.ShimID,
			Error:  fmt.Sprintf("unknown envelope type: %q", env.Type),
		}, nil
	}
}

func (r *Router) handleRegister(env *ipc.AegisEnvelope) (*ipc.AegisEnvelope, error) {
	if env.ShimID == "" {
		return &ipc.AegisEnvelope{
			Type:  "error",
			Error: "register requires shim_id",
		}, nil
	}

	state := r.sessions.Register(env.ShimID, env.AgentID, env.ToolName)
	r.logger.Info("session registered",
		"shim_id", env.ShimID,
		"agent_id", env.AgentID,
		"session_id", state.SessionID,
	)

	return &ipc.AegisEnvelope{
		Type:      "registered",
		ShimID:    env.ShimID,
		SessionID: state.SessionID,
	}, nil
}

func (r *Router) handleMCPRequest(env *ipc.AegisEnvelope) (*ipc.AegisEnvelope, error) {
	_, ok := r.sessions.Get(env.ShimID)
	if !ok {
		return &ipc.AegisEnvelope{
			Type:   "error",
			ShimID: env.ShimID,
			Error:  "shim not registered; send register first",
		}, nil
	}

	r.logger.Info("mcp_request received",
		"shim_id", env.ShimID,
		"request_id", env.RequestID,
		"tool", env.ToolName,
	)

	toolName, args := extractToolCall(env.MCPMessage)

	if denied, msg := r.checkPolicy(toolName, args); denied {
		r.logger.Warn("request blocked by policy",
			"shim_id", env.ShimID,
			"tool", toolName,
			"reason", msg,
		)
		denyResp := buildDenyResponse(env.MCPMessage, msg)
		return &ipc.AegisEnvelope{
			Type:       "mcp_response",
			ShimID:     env.ShimID,
			RequestID:  env.RequestID,
			SessionID:  env.SessionID,
			MCPMessage: denyResp,
		}, nil
	}

	result, err := r.executor.Execute(context.Background(), env.ToolName, env.MCPMessage)
	if err != nil {
		r.logger.Error("executor error", "error", err, "tool", env.ToolName)
		errResp := buildErrorResponse(env.MCPMessage, err.Error())
		return &ipc.AegisEnvelope{
			Type:       "mcp_response",
			ShimID:     env.ShimID,
			RequestID:  env.RequestID,
			SessionID:  env.SessionID,
			MCPMessage: errResp,
		}, nil
	}

	return &ipc.AegisEnvelope{
		Type:       "mcp_response",
		ShimID:     env.ShimID,
		RequestID:  env.RequestID,
		SessionID:  env.SessionID,
		MCPMessage: result,
	}, nil
}

func (r *Router) handleCancel(env *ipc.AegisEnvelope) (*ipc.AegisEnvelope, error) {
	r.logger.Info("cancel received",
		"shim_id", env.ShimID,
		"request_id", env.RequestID,
	)

	return &ipc.AegisEnvelope{
		Type:      "cancelled",
		ShimID:    env.ShimID,
		RequestID: env.RequestID,
	}, nil
}

// checkPolicy applies hardcoded policy rules.
// Returns (denied bool, reason string).
func (r *Router) checkPolicy(toolName string, args map[string]any) (bool, string) {
	if toolName == "shell_exec" {
		for _, v := range args {
			if s, ok := v.(string); ok && strings.Contains(s, "rm -rf") {
				return true, "Blocked by Aegis: dangerous pattern 'rm -rf' detected"
			}
		}
	}
	return false, ""
}

// extractToolCall parses the MCP JSON-RPC message to get the tool name and arguments.
func extractToolCall(mcpMessage json.RawMessage) (string, map[string]any) {
	var msg struct {
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(mcpMessage, &msg); err != nil {
		return "", nil
	}
	return msg.Params.Name, msg.Params.Arguments
}

// extractRequestID gets the id field from the MCP JSON-RPC message.
func extractRequestID(mcpMessage json.RawMessage) json.RawMessage {
	var msg struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(mcpMessage, &msg); err != nil {
		return json.RawMessage(`null`)
	}
	if msg.ID == nil {
		return json.RawMessage(`null`)
	}
	return msg.ID
}

func buildDenyResponse(mcpMessage json.RawMessage, reason string) json.RawMessage {
	id := extractRequestID(mcpMessage)
	resp := map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": reason},
			},
			"isError": true,
		},
		"id": id,
	}
	data, _ := json.Marshal(resp)
	return data
}

func buildErrorResponse(mcpMessage json.RawMessage, errMsg string) json.RawMessage {
	id := extractRequestID(mcpMessage)
	resp := map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": "Executor error: " + errMsg},
			},
			"isError": true,
		},
		"id": id,
	}
	data, _ := json.Marshal(resp)
	return data
}
