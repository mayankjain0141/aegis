#!/bin/bash
set -e
export PATH="/opt/homebrew/bin:$PATH"

make build 2>/dev/null

echo "═══════════════════════════════════════════"
echo "  AEGIS DEMO (scripted, no API key needed)"
echo "═══════════════════════════════════════════"
echo ""

echo "━━━ Normal Operation (should ALLOW) ━━━"
(printf '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}},"id":1}\n{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls -la"}},"id":2}\n'; sleep 1) | bin/aegis-shim --agent-id demo --policies policies/default.yaml -- ./bin/mock-tool 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    if 'result' in msg and msg.get('id') == 2:
        r = msg['result']
        if r.get('isError'):
            print(f'  ✗ BLOCKED: {r[\"content\"][0][\"text\"]}')
        else:
            print(f'  ✓ ALLOWED: {r[\"content\"][0][\"text\"]}')
"

echo ""
echo "━━━ Attack Scenario (should BLOCK) ━━━"
(printf '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}},"id":1}\n{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"rm -rf /"}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read","arguments":{"path":".env"}},"id":3}\n'; sleep 1) | bin/aegis-shim --agent-id demo --policies policies/default.yaml -- ./bin/mock-tool 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    if 'result' in msg and msg.get('id', 0) >= 2:
        r = msg['result']
        if r.get('isError'):
            print(f'  ✗ BLOCKED: {r[\"content\"][0][\"text\"]}')
        else:
            print(f'  ✓ ALLOWED: {r[\"content\"][0][\"text\"]}')
"

echo ""
echo "━━━ Running full attack suite ━━━"
bin/aegis-daemon --policies policies/default.yaml --http-port 0 &>/dev/null &
DAEMON_PID=$!
trap "kill $DAEMON_PID 2>/dev/null; wait $DAEMON_PID 2>/dev/null" EXIT
sleep 1
python3 agent/harness.py

echo ""
echo "═══════════════════════════════════════════"
echo "  DEMO COMPLETE"
echo "═══════════════════════════════════════════"
