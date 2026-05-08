#!/bin/bash
set -e

go build -o /tmp/aegis-daemon-test ./cmd/daemon
go build -o /tmp/aegis-shim-test ./cmd/shim

/tmp/aegis-daemon-test --config=aegis.yaml &>/dev/null &
trap "kill $! 2>/dev/null" EXIT
sleep 0.5

RESULT=$(echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":1}' | /tmp/aegis-shim-test --tool=shell-mcp --agent-id=hello-test)

echo "Response: $RESULT"
echo "$RESULT" | grep -q "tool executed successfully" && echo "✓ Hello World IPC: PASS" || { echo "✗ FAIL"; exit 1; }
