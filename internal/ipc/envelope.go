package ipc

import "encoding/json"

// AegisEnvelope wraps MCP messages for shim↔daemon communication over Unix socket.
// Uses length-prefixed framing: [4 bytes uint32 big-endian length][N bytes JSON payload]
type AegisEnvelope struct {
	Type       string          `json:"type"`                  // "register", "registered", "mcp_request", "mcp_response", "evaluate", "evaluation", "cancel", "cancelled"
	ShimID     string          `json:"shim_id,omitempty"`
	AgentID    string          `json:"agent_id,omitempty"`
	ToolName   string          `json:"tool_name,omitempty"`
	RequestID  string          `json:"request_id,omitempty"`
	SessionID  string          `json:"session_id,omitempty"`
	MCPMessage json.RawMessage `json:"mcp_message,omitempty"` // Raw MCP JSON-RPC message
	Error      string          `json:"error,omitempty"`
	Evaluation *EvaluationResult `json:"evaluation,omitempty"` // Response for "evaluate" requests
}

// EvaluationResult is returned by the daemon for policy evaluation requests.
type EvaluationResult struct {
	Action      string  `json:"action"`       // "allow", "deny", "escalate"
	Policy      string  `json:"policy"`       // which rule matched
	RiskScore   float64 `json:"risk_score"`
	Reason      string  `json:"reason"`       // human-readable explanation
	DenyMessage string  `json:"deny_message"` // pre-formatted denial text for isError response
}
