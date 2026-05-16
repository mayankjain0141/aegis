#!/bin/bash
set -e
mkdir -p .cursor/hooks
go build -o .cursor/hooks/aegis ./cmd/hook/
chmod +x .cursor/hooks/aegis
echo "Hook binary installed at .cursor/hooks/aegis"
