package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mayjain/aegis/internal/approval"
	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/internal/risk"
	"github.com/mayjain/aegis/internal/session"
	"github.com/mayjain/aegis/internal/trace"
)

// Router handles incoming envelopes and dispatches them.
type Router struct {
	sessions        *session.Registry
	executor        *Executor
	policyEvaluator policy.PolicyEvaluator
	riskScorer      *risk.CompositeScorer
	collector       trace.Collector
	approvalGate    *approval.Gate
	metrics         *Metrics
	logger          *slog.Logger
	onTrace         func([]byte) // called after each trace emit with JSON
}

func NewRouter(executor *Executor, policyEval policy.PolicyEvaluator, riskScorer *risk.CompositeScorer, metrics *Metrics, logger *slog.Logger) *Router {
	return &Router{
		sessions:        session.NewRegistry(),
		executor:        executor,
		policyEvaluator: policyEval,
		riskScorer:      riskScorer,
		metrics:         metrics,
		logger:          logger,
	}
}

// SetCollector attaches a trace collector to the router.
func (r *Router) SetCollector(c trace.Collector) {
	r.collector = c
}

// SetOnTrace sets a callback invoked with JSON-serialized trace events.
func (r *Router) SetOnTrace(fn func([]byte)) {
	r.onTrace = fn
}

// SetApprovalGate attaches a human approval gate to the router.
func (r *Router) SetApprovalGate(gate *approval.Gate) {
	r.approvalGate = gate
}

// ApprovalGate returns the router's approval gate (may be nil).
func (r *Router) ApprovalGate() *approval.Gate {
	return r.approvalGate
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
	case "evaluate":
		return r.handleEvaluate(env)
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

	r.metrics.CallsTotal.Add(1)

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
		latency := time.Since(start)
		r.emitTrace(env, toolName, riskScore, "error", nil, latency, err)
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
		r.metrics.DeniedTotal.Add(1)
		r.emitTrace(env, toolName, riskScore, string(decision.Action), decision, latency, nil)
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
		r.metrics.DeniedTotal.Add(1)
		r.emitTrace(env, toolName, riskScore, string(decision.Action), decision, latency, nil)
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
		if r.approvalGate == nil {
			r.emitTrace(env, toolName, riskScore, string(decision.Action), decision, latency, nil)
			reason := "Blocked by Aegis: human approval not configured"
			denyResp := buildDenyResponse(env.MCPMessage, reason)
			return &ipc.AegisEnvelope{
				Type:       "mcp_response",
				ShimID:     env.ShimID,
				RequestID:  env.RequestID,
				SessionID:  env.SessionID,
				MCPMessage: denyResp,
			}, nil
		}

		pa := &approval.PendingApproval{
			RequestID:   env.RequestID,
			AgentID:     env.AgentID,
			Tool:        toolName,
			ArgsSummary: string(argsJSON),
			RiskScore:   riskScore,
		}

		approvalResp, escalateErr := r.approvalGate.Escalate(context.Background(), pa)
		latency = time.Since(start)

		if escalateErr != nil {
			r.emitTrace(env, toolName, riskScore, "error", decision, latency, escalateErr)
			errResp := buildErrorResponse(env.MCPMessage, "approval error: "+escalateErr.Error())
			return &ipc.AegisEnvelope{
				Type:       "mcp_response",
				ShimID:     env.ShimID,
				RequestID:  env.RequestID,
				SessionID:  env.SessionID,
				MCPMessage: errResp,
			}, nil
		}

		if approvalResp.Action != "approve" {
			r.emitTrace(env, toolName, riskScore, "deny", decision, latency, nil)
			reason := fmt.Sprintf("Blocked by Aegis: human denied (%s)", approvalResp.Reason)
			denyResp := buildDenyResponse(env.MCPMessage, reason)
			return &ipc.AegisEnvelope{
				Type:       "mcp_response",
				ShimID:     env.ShimID,
				RequestID:  env.RequestID,
				SessionID:  env.SessionID,
				MCPMessage: denyResp,
			}, nil
		}

		r.emitTrace(env, toolName, riskScore, "approve", decision, latency, nil)

	default:
		// ActionAllow — proceed to executor
	}

	result, execErr := r.executor.Execute(context.Background(), env.ToolName, env.MCPMessage)
	latency = time.Since(start)
	r.emitTrace(env, toolName, riskScore, string(decision.Action), decision, latency, execErr)

	if execErr != nil {
		r.logger.Error("executor error", "error", execErr, "tool", env.ToolName)
		errResp := buildErrorResponse(env.MCPMessage, execErr.Error())
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

func (r *Router) emitTrace(env *ipc.AegisEnvelope, toolName string, riskScore float64, decision string, pd *policy.PolicyDecision, latency time.Duration, err error) {
	if r.collector == nil {
		return
	}
	ev := &trace.TraceEvent{
		SessionID: env.SessionID,
		RequestID: env.RequestID,
		AgentID:   env.AgentID,
		Timestamp: time.Now(),
		Tool:      toolName,
		RiskScore: riskScore,
		Decision:  decision,
		Mode:      "enforce",
		LatencyMs: int(latency.Milliseconds()),
	}
	if pd != nil {
		ev.PolicyID = pd.PolicyName
		ev.PolicyVersion = pd.PolicyVersion
	}
	if err != nil {
		ev.Error = err.Error()
	}
	r.collector.Emit(ev)

	if r.onTrace != nil {
		if data, jsonErr := json.Marshal(ev); jsonErr == nil {
			r.onTrace(data)
		}
	}
}

func (r *Router) handleEvaluate(env *ipc.AegisEnvelope) (*ipc.AegisEnvelope, error) {
	sess, ok := r.sessions.Get(env.ShimID)
	if !ok {
		return &ipc.AegisEnvelope{
			Type:   "error",
			ShimID: env.ShimID,
			Error:  "shim not registered; send register first",
		}, nil
	}

	r.metrics.CallsTotal.Add(1)

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
	latency := time.Since(start)

	if err != nil {
		r.logger.Error("policy evaluation error", "error", err, "tool", toolName)
		r.emitTrace(env, toolName, riskScore, "error", nil, latency, err)
		return &ipc.AegisEnvelope{
			Type:      "evaluation",
			ShimID:    env.ShimID,
			RequestID: env.RequestID,
			Evaluation: &ipc.EvaluationResult{
				Action:      "deny",
				RiskScore:   riskScore,
				Reason:      "internal policy error",
				DenyMessage: "Aegis internal: policy evaluation failed, action denied for safety",
			},
		}, nil
	}

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
		r.metrics.DeniedTotal.Add(1)
		r.emitTrace(env, toolName, riskScore, "deny", decision, latency, nil)
		return &ipc.AegisEnvelope{
			Type:      "evaluation",
			ShimID:    env.ShimID,
			RequestID: env.RequestID,
			Evaluation: &ipc.EvaluationResult{
				Action:      "deny",
				Policy:      decision.PolicyName,
				RiskScore:   riskScore,
				Reason:      decision.Reason,
				DenyMessage: fmt.Sprintf("Blocked by Aegis policy '%s': %s", decision.PolicyName, decision.Reason),
			},
		}, nil

	case policy.ActionThrottle:
		r.metrics.DeniedTotal.Add(1)
		r.emitTrace(env, toolName, riskScore, "throttle", decision, latency, nil)
		return &ipc.AegisEnvelope{
			Type:      "evaluation",
			ShimID:    env.ShimID,
			RequestID: env.RequestID,
			Evaluation: &ipc.EvaluationResult{
				Action:      "deny",
				Policy:      decision.PolicyName,
				RiskScore:   riskScore,
				Reason:      decision.Reason,
				DenyMessage: fmt.Sprintf("Blocked by Aegis: rate limited (%s)", decision.Reason),
			},
		}, nil

	case policy.ActionEscalateHuman:
		if r.approvalGate == nil {
			r.emitTrace(env, toolName, riskScore, "escalate", decision, latency, nil)
			return &ipc.AegisEnvelope{
				Type:      "evaluation",
				ShimID:    env.ShimID,
				RequestID: env.RequestID,
				Evaluation: &ipc.EvaluationResult{
					Action:      "deny",
					Policy:      decision.PolicyName,
					RiskScore:   riskScore,
					Reason:      "human approval not configured",
					DenyMessage: "Blocked by Aegis: human approval gate not available",
				},
			}, nil
		}

		pa := &approval.PendingApproval{
			RequestID:   env.RequestID,
			AgentID:     env.AgentID,
			Tool:        toolName,
			ArgsSummary: string(argsJSON),
			RiskScore:   riskScore,
		}

		approvalResp, escalateErr := r.approvalGate.Escalate(context.Background(), pa)
		latency = time.Since(start)

		if escalateErr != nil || approvalResp.Action != "approve" {
			reason := "human denied"
			if escalateErr != nil {
				reason = escalateErr.Error()
			} else if approvalResp.Reason != "" {
				reason = approvalResp.Reason
			}
			r.emitTrace(env, toolName, riskScore, "deny", decision, latency, nil)
			return &ipc.AegisEnvelope{
				Type:      "evaluation",
				ShimID:    env.ShimID,
				RequestID: env.RequestID,
				Evaluation: &ipc.EvaluationResult{
					Action:      "deny",
					Policy:      decision.PolicyName,
					RiskScore:   riskScore,
					Reason:      reason,
					DenyMessage: fmt.Sprintf("Blocked by Aegis: %s", reason),
				},
			}, nil
		}

		r.emitTrace(env, toolName, riskScore, "approve", decision, latency, nil)
		return &ipc.AegisEnvelope{
			Type:      "evaluation",
			ShimID:    env.ShimID,
			RequestID: env.RequestID,
			Evaluation: &ipc.EvaluationResult{
				Action:    "allow",
				Policy:    decision.PolicyName,
				RiskScore: riskScore,
				Reason:    "approved by human",
			},
		}, nil

	default:
		// ActionAllow
		r.emitTrace(env, toolName, riskScore, "allow", decision, latency, nil)
		return &ipc.AegisEnvelope{
			Type:      "evaluation",
			ShimID:    env.ShimID,
			RequestID: env.RequestID,
			Evaluation: &ipc.EvaluationResult{
				Action:    "allow",
				Policy:    decision.PolicyName,
				RiskScore: riskScore,
				Reason:    decision.Reason,
			},
		}, nil
	}
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
