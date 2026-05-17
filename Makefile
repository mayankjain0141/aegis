.PHONY: build install smoke test test-attacks bench up down logs lint fmt ci hello integration eval-bench eval hook demo-ui demo-terminal

build:
	go build -buildvcs=false -o bin/aegis-daemon ./cmd/daemon
	go build -buildvcs=false -o bin/aegis-shim ./cmd/shim
	go build -buildvcs=false -o bin/aegis ./cmd/aegis
	go build -buildvcs=false -o .cursor/hooks/aegis ./cmd/hook

install:
	go install ./cmd/daemon
	go install ./cmd/shim
	go install ./cmd/watch

test:
	go test ./...

smoke:
	go test ./test/e2e/... -v -count=1 -timeout=10s

test-attacks:
	@bash scripts/test-attacks.sh

bench:
	go test -bench=. -benchmem ./test/bench/...

hello:
	@bash scripts/hello.sh

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
	@bash scripts/demo.sh

demo-live:
	@bash scripts/demo-live.sh

# Quality
lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

ci: lint test build

integration:
	go test ./test/integration/... -v -count=1 -timeout=30s

demo-e2e: build
	@bash scripts/demo-e2e.sh

demo-hitl: build
	@bash scripts/demo-hitl.sh

eval-bench: build
	@go run ./cmd/eval-bench --corpus testdata/eval/ --verbose --threshold 0.0

# V2 eval targets
eval:
	@go run ./cmd/eval-bench/ --corpus testdata/eval/ --threshold 0.9

eval-regression:
	@go run ./cmd/eval-bench/ --corpus testdata/eval/ --baseline .aegis/eval-baseline.json

eval-save-baseline:
	@go run ./cmd/eval-bench/ --corpus testdata/eval/ --save-baseline .aegis/eval-baseline.json --threshold 0.0

hook:
	@mkdir -p .cursor/hooks
	@go build -o .cursor/hooks/aegis ./cmd/hook/
	@chmod +x .cursor/hooks/aegis
	@echo "Hook installed at .cursor/hooks/aegis"

# ── Demo targets ──────────────────────────────────────────────────────────

demo-ui:
	@echo "Building Aegis Control Plane dashboard..."
	@go build -o /tmp/aegis-demo-ui ./cmd/demo-ui/
	@echo "Starting at http://localhost:7474"
	@/tmp/aegis-demo-ui

demo-terminal:
	@go run ./cmd/demo-v2/
