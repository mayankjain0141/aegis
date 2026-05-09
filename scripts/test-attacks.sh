#!/bin/bash
set -e
export PATH="/opt/homebrew/bin:$PATH"

make build

bin/aegis-daemon --policies policies/default.yaml --http-port 0 &>/dev/null &
DAEMON_PID=$!
trap "kill $DAEMON_PID 2>/dev/null; wait $DAEMON_PID 2>/dev/null" EXIT
sleep 1

python3 agent/harness.py
