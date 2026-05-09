#!/bin/bash
set -e
export PATH="/opt/homebrew/bin:$PATH"

make build 2>/dev/null

rm -f /tmp/aegis.sock
bin/aegis-daemon --policies policies/default.yaml --http-port 0 &>/dev/null &
DAEMON_PID=$!
trap "kill $DAEMON_PID 2>/dev/null; rm -f /tmp/aegis.sock" EXIT
sleep 1

python3 agent/harness.py
