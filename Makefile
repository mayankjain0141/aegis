.PHONY: build install test smoke test-attacks bench lint fmt ci integration eval eval-bench eval-regression eval-save-baseline hook demo-ui up down logs

build:
	go build -buildvcs=false -o bin/aegis-daemon ./cmd/daemon
	go build -buildvcs=false -o bin/aegis ./cmd/aegis
	go build -buildvcs=false -o .cursor/hooks/aegis ./cmd/hook

install:
	go install ./cmd/daemon
	go install ./cmd/aegis
	go install ./cmd/hook

test:
	go test ./...

smoke:
	go test ./test/e2e/... -v -count=1 -timeout=10s

test-attacks:
	@bash scripts/test-attacks.sh

bench:
	go test -bench=. -benchmem ./test/bench/...

integration:
	go test ./test/integration/... -v -count=1 -timeout=30s

# ── Eval ──────────────────────────────────────────────────────────────────────

eval:
	@go run ./cmd/eval-bench/ --corpus testdata/eval/ --threshold 0.9

eval-bench:
	@go run ./cmd/eval-bench/ --corpus testdata/eval/ --verbose --threshold 0.0

eval-regression:
	@go run ./cmd/eval-bench/ --corpus testdata/eval/ --baseline .aegis/eval-baseline.json

eval-save-baseline:
	@go run ./cmd/eval-bench/ --corpus testdata/eval/ --save-baseline .aegis/eval-baseline.json --threshold 0.0

# ── Hook ──────────────────────────────────────────────────────────────────────

hook:
	@mkdir -p .cursor/hooks
	@go build -o .cursor/hooks/aegis ./cmd/hook/
	@chmod +x .cursor/hooks/aegis
	@echo "Hook installed at .cursor/hooks/aegis"

# ── Demo ──────────────────────────────────────────────────────────────────────

demo-ui:
	@go build -o /tmp/aegis-demo-ui ./cmd/demo-ui/
	@/tmp/aegis-demo-ui

# ── Infrastructure ────────────────────────────────────────────────────────────

up:
	docker compose up -d

down:
	docker compose down -v

logs:
	docker compose logs -f

# ── Quality ───────────────────────────────────────────────────────────────────

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

ci: lint test build
