#!/bin/bash
set -e

# Load env
[ -f .env ] && source .env

# Build
make build 2>/dev/null

# Start daemon, run agent, cleanup
rm -f /tmp/aegis.sock
bin/aegis-daemon --policies policies/default.yaml &>/dev/null &
trap "kill $! 2>/dev/null" EXIT
sleep 1

python3 agent/runner.py "$@"
