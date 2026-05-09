#!/bin/bash
set -e

make build 2>/dev/null

RESULT=$( (printf '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}\n{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"hello from aegis"}},"id":2}\n'; sleep 2) | bin/aegis-shim --agent-id hello-test --policies policies/default.yaml -- ./bin/mock-tool 2>/dev/null)

if echo "$RESULT" | grep -q '"executed: hello from aegis"'; then
    echo "✓ Hello World IPC: PASS"
else
    echo "✗ Hello World IPC: FAIL"
    echo "Got: $RESULT"
    exit 1
fi
