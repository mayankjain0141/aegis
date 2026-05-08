.PHONY: build smoke test test-e2e test-attacks bench up down logs watch demo lint fmt ci hello

# Phase 0
hello:
	@echo "TODO: IPC smoke test"

# Core development
build:
	go build -o bin/aegis-daemon ./cmd/daemon
	go build -o bin/aegis-shim ./cmd/shim
	go build -o bin/aegis-watch ./cmd/watch

smoke:
	@echo "TODO: <5s smoke test"

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
	docker compose down

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
