package errs

// JSON-RPC error codes for infrastructure failures only.
// Policy denials use CallToolResult with isError=true (not JSON-RPC errors).
const (
	ErrToolUnavailable = -32004 // Circuit breaker open, tool server down
	ErrRateLimited     = -32005 // Sustained overload
	ErrDaemonInternal  = -32006 // Aegis internal error (bug)
)

// DenyResult constructs an MCP CallToolResult with isError=true for policy denials.
func DenyResult(reason string) map[string]any {
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": reason},
		},
		"isError": true,
	}
}
