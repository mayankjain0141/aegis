#!/bin/bash
set -e

[ -f .env ] && source .env

make build 2>/dev/null

bin/aegis-daemon --policies policies/default.yaml &>/dev/null &
trap "kill $! 2>/dev/null" EXIT
sleep 1

python3 agent/runner.py "$@"
