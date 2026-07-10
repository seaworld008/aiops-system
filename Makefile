.PHONY: test test-race test-integration vet build check format run

test:
	go test ./...

test-race:
	go test -race -shuffle=on -count=1 ./...

test-integration:
	@test -n "$$AIOPS_TEST_POSTGRES_DSN" || (echo "AIOPS_TEST_POSTGRES_DSN is required" >&2; exit 1)
	go test -race -count=1 ./internal/store/postgres ./internal/execution/postgres

vet:
	go vet ./...

build:
	go build ./cmd/control-plane ./cmd/worker ./cmd/runner

check: test-race vet build

format:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

run:
	go run ./cmd/control-plane
