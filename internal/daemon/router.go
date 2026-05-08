package daemon

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/session"
)

// Router handles incoming envelopes and dispatches them.
type Router struct {
	sessions *session.Registry
	logger   *slog.Logger
}

func NewRouter(logger *slog.Logger) *Router {
	return &Router{
		sessions: session.NewRegistry(),
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

	// Phase 1A: echo the MCP message back (tool execution comes in Phase 1C)
	return &ipc.AegisEnvelope{
		Type:       "mcp_response",
		ShimID:     env.ShimID,
		RequestID:  env.RequestID,
		SessionID:  env.SessionID,
		MCPMessage: env.MCPMessage,
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
