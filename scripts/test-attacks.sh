#!/bin/bash
set -e

make build 2>/dev/null
rm -f /tmp/aegis.sock

bin/aegis-daemon --policies policies/default.yaml &>/dev/null &
trap "kill $! 2>/dev/null" EXIT
sleep 1

python3 agent/harness.py
