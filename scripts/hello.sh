#!/bin/bash
set -e

make build 2>/dev/null

bin/aegis-daemon --policies policies/default.yaml &>/dev/null &
trap "kill $! 2>/dev/null" EXIT
sleep 1

RESULT=$(echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":1}' | bin/aegis-shim --tool=shell-mcp --agent-id=hello-test)

echo "Response: $RESULT"
echo "$RESULT" | grep -q "tool executed successfully" && echo "✓ Hello World IPC: PASS" || { echo "✗ FAIL"; exit 1; }
