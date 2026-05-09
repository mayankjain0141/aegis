.PHONY: build install smoke test test-attacks bench up down logs watch demo demo-live lint fmt ci hello integration demo-e2e

build:
	go build -buildvcs=false -o bin/aegis-daemon ./cmd/daemon
	go build -buildvcs=false -o bin/aegis-shim ./cmd/shim
	go build -buildvcs=false -o bin/aegis-watch ./cmd/watch
	go build -buildvcs=false -o bin/mock-tool ./test/mock
	go build -buildvcs=false -o bin/aegis-real-tool ./cmd/real-tool
	go build -buildvcs=false -o bin/demo-e2e ./cmd/demo-e2e

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
