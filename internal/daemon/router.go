package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/internal/risk"
	"github.com/mayjain/aegis/internal/session"
)

// Router handles incoming envelopes and dispatches them.
type Router struct {
	sessions        *session.Registry
	executor        *Executor
	policyEvaluator policy.PolicyEvaluator
	riskScorer      *risk.CompositeScorer
	logger          *slog.Logger
}

func NewRouter(executor *Executor, policyEval policy.PolicyEvaluator, riskScorer *risk.CompositeScorer, logger *slog.Logger) *Router {
	return &Router{
		sessions:        session.NewRegistry(),
		executor:        executor,
		policyEvaluator: policyEval,
		riskScorer:      riskScorer,
		logger:          logger,
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
	sess, ok := r.sessions.Get(env.ShimID)
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

	start := time.Now()

	toolName, args := extractToolCall(env.MCPMessage)
	argsJSON, _ := json.Marshal(args)

	sessCtx := sess.GetContext()

	riskScore := r.riskScorer.Score(context.Background(), toolName, string(argsJSON), sessCtx.CallsLastMinute)

	policyReq := &policy.ToolCallRequest{
		AgentID:   env.AgentID,
		Tool:      toolName,
		Arguments: string(argsJSON),
		RequestID: env.RequestID,
		SessionCtx: &policy.SessionContext{
			CallsLastMinute: sessCtx.CallsLastMinute,
			CallsLastHour:   sessCtx.CallsLastHour,
			RecentTools:     sessCtx.RecentTools,
			SessionStarted:  sessCtx.SessionStarted.Format(time.RFC3339),
		},
	}

	decision, err := r.policyEvaluator.Evaluate(context.Background(), policyReq)
	if err != nil {
		r.logger.Error("policy evaluation error", "error", err, "tool", toolName)
		errResp := buildErrorResponse(env.MCPMessage, "internal policy error")
		return &ipc.AegisEnvelope{
			Type:       "mcp_response",
			ShimID:     env.ShimID,
			RequestID:  env.RequestID,
			SessionID:  env.SessionID,
			MCPMessage: errResp,
		}, nil
	}

	latency := time.Since(start)
	r.logger.Info("policy decision",
		"tool", toolName,
		"risk_score", riskScore,
		"decision", decision.Action,
		"policy_name", decision.PolicyName,
		"latency_us", latency.Microseconds(),
	)

	sess.RecordCall(toolName, riskScore, string(decision.Action))

	switch decision.Action {
	case policy.ActionDeny:
		reason := fmt.Sprintf("Blocked by Aegis: %s", decision.Reason)
		denyResp := buildDenyResponse(env.MCPMessage, reason)
		return &ipc.AegisEnvelope{
			Type:       "mcp_response",
			ShimID:     env.ShimID,
			RequestID:  env.RequestID,
			SessionID:  env.SessionID,
			MCPMessage: denyResp,
		}, nil

	case policy.ActionThrottle:
		reason := fmt.Sprintf("Blocked by Aegis: rate limited (%s)", decision.Reason)
		denyResp := buildDenyResponse(env.MCPMessage, reason)
		return &ipc.AegisEnvelope{
			Type:       "mcp_response",
			ShimID:     env.ShimID,
			RequestID:  env.RequestID,
			SessionID:  env.SessionID,
			MCPMessage: denyResp,
		}, nil

	case policy.ActionEscalateHuman:
		reason := "Blocked by Aegis: human approval not yet implemented"
		denyResp := buildDenyResponse(env.MCPMessage, reason)
		return &ipc.AegisEnvelope{
			Type:       "mcp_response",
			ShimID:     env.ShimID,
			RequestID:  env.RequestID,
			SessionID:  env.SessionID,
			MCPMessage: denyResp,
		}, nil

	default:
		// ActionAllow — proceed to executor
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
