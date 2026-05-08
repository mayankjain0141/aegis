package ipc

import "encoding/json"

// AegisEnvelope wraps MCP messages for shim↔daemon communication over Unix socket.
// Uses length-prefixed framing: [4 bytes uint32 big-endian length][N bytes JSON payload]
type AegisEnvelope struct {
	Type       string          `json:"type"`                  // "register", "registered", "mcp_request", "mcp_response", "cancel", "cancelled"
	ShimID     string          `json:"shim_id,omitempty"`
	AgentID    string          `json:"agent_id,omitempty"`
	ToolName   string          `json:"tool_name,omitempty"`
	RequestID  string          `json:"request_id,omitempty"`
	SessionID  string          `json:"session_id,omitempty"`
	MCPMessage json.RawMessage `json:"mcp_message,omitempty"` // Raw MCP JSON-RPC message
	Error      string          `json:"error,omitempty"`
}
