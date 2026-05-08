.PHONY: build smoke test test-attacks bench up down logs watch demo demo-live lint fmt ci hello

build:
	go build -o bin/aegis-daemon ./cmd/daemon
	go build -o bin/aegis-shim ./cmd/shim
	go build -o bin/aegis-watch ./cmd/watch

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
