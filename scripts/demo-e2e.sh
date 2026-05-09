#!/bin/bash
set -e

echo "Building Aegis..."
make build 2>&1 | tail -1

# Kill any stale daemon
pkill -f "aegis-daemon" 2>/dev/null || true
sleep 0.3

# Start daemon (socket cleanup is handled by the daemon itself on start/stop)
bin/aegis-daemon --policies policies/default.yaml --http-port 8080 &
DAEMON_PID=$!
trap "kill $DAEMON_PID 2>/dev/null; wait $DAEMON_PID 2>/dev/null" EXIT

# Wait for daemon to be ready
for i in $(seq 1 30); do
  if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

echo ""
echo "  Dashboard: http://localhost:8080"
echo ""

# Open browser (macOS or Linux)
open http://localhost:8080 2>/dev/null || xdg-open http://localhost:8080 2>/dev/null || true
sleep 0.5

# Run demo
bin/demo-e2e --socket /tmp/aegis.sock --policies policies/default.yaml

echo ""
echo "  Dashboard still live at http://localhost:8080 — Ctrl+C to stop"
echo ""
wait $DAEMON_PID 2>/dev/null
