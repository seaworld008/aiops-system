.PHONY: test test-race test-integration vet build runner-images check format run

GO_BUILD_IMAGE ?= docker.io/library/golang:1.26.5-bookworm
READ_RUNNER_IMAGE ?= aiops-read-runner:dev
WRITE_RUNNER_IMAGE ?= aiops-write-runner:dev

test:
	go test ./...

test-race:
	go test -race -shuffle=on -count=1 ./...

test-integration:
	@test -n "$$AIOPS_TEST_POSTGRES_DSN" || (echo "AIOPS_TEST_POSTGRES_DSN is required" >&2; exit 1)
	go test -race -count=1 ./internal/store/postgres ./internal/execution/postgres ./internal/investigation/postgres ./internal/runneridentity/postgres ./internal/readtask/postgres ./internal/assetcatalog/postgres

vet:
	go vet ./...

build:
	go build ./cmd/control-plane ./cmd/worker ./cmd/read-runner ./cmd/write-runner ./cmd/executor

runner-images:
	docker build --build-arg GO_BUILD_IMAGE="$(GO_BUILD_IMAGE)" --file build/package/read-runner/Dockerfile --tag "$(READ_RUNNER_IMAGE)" .
	docker build --build-arg GO_BUILD_IMAGE="$(GO_BUILD_IMAGE)" --file build/package/write-runner/Dockerfile --tag "$(WRITE_RUNNER_IMAGE)" .

check: test-race vet build

format:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

run:
	go run ./cmd/control-plane
