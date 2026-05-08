.PHONY: build smoke test test-e2e test-attacks bench up down logs watch demo lint fmt ci hello

# Phase 0
hello:
	@rm -f /tmp/aegis.sock
	@go build -o /tmp/aegis-daemon-test ./cmd/daemon
	@go build -o /tmp/aegis-shim-test ./cmd/shim
	@/tmp/aegis-daemon-test --config=aegis.yaml & DAEMON_PID=$$!; \
		sleep 0.3; \
		RESULT=$$(echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":1}' | /tmp/aegis-shim-test --tool=shell-mcp --agent-id=hello-test); \
		kill $$DAEMON_PID 2>/dev/null; \
		wait $$DAEMON_PID 2>/dev/null; \
		echo "Response: $$RESULT"; \
		if echo "$$RESULT" | grep -q 'tool executed successfully'; then \
			echo "✓ Hello World IPC: PASS"; \
		else \
			echo "✗ Hello World IPC: FAIL"; exit 1; \
		fi

# Core development
build:
	go build -o bin/aegis-daemon ./cmd/daemon
	go build -o bin/aegis-shim ./cmd/shim
	go build -o bin/aegis-watch ./cmd/watch

smoke:
	@export PATH="/opt/homebrew/bin:$$PATH" && go test ./test/e2e/... -v -count=1 -timeout=10s

test:
	go test ./...
	cd agent && python -m pytest

test-e2e:
	@echo "TODO: Full E2E with Docker"

test-attacks:
	@echo "TODO: Attack simulator"

bench:
	go test -bench=. -benchmem ./test/bench/...

# Running
up:
	docker compose up -d

down:
	docker compose down -v

logs:
	docker compose logs -f

watch:
	go run ./cmd/watch

demo:
	@echo "TODO: Full demo flow"

# Quality
lint:
	golangci-lint run ./...
	cd agent && ruff check .

fmt:
	gofmt -w .
	cd agent && black .

ci: lint test build
