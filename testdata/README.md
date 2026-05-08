# MCP Test Data

`mcp_captured.jsonl` contains realistic MCP JSON-RPC messages for testing.
These represent the messages Claude Code sends/receives when interacting with
MCP tool servers.

## Used by

- `internal/ipc/` tests — golden file validation of envelope framing
- Policy engine tests — benign vs dangerous input classification
- Risk scorer tests — score computation against known inputs
- Attack simulator — baseline dangerous patterns

## Format

One JSON-RPC message per line (newline-delimited JSON).

## Message Categories

- Lines 1-2: Initialize handshake
- Lines 3-4: tools/list request and response
- Lines 5-12: Benign tool calls (ls, file_read, echo, file_write)
- Lines 13-21: Dangerous tool calls (rm -rf, .env access, exfiltration, injection)
- Line 22: Error response (isError=true)
- Line 23: Cancellation notification
- Lines 24-29: Concurrent requests and responses
- Lines 30-35: Additional attack patterns (shutdown, dd, ssh keys, chmod, code injection)
