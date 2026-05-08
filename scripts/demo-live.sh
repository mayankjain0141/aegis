#!/bin/bash
set -e

[ -f .env ] && source .env

make build 2>/dev/null
go build -o bin/mock-tool ./test/mock 2>/dev/null

python3 agent/runner.py "$@"
