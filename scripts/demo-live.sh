#!/bin/bash
set -e

[ -f .env ] && source .env

make build 2>/dev/null

python3 agent/runner.py "$@"
