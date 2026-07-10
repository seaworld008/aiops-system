.PHONY: test vet build run

test:
	go test ./...

vet:
	go vet ./...

build:
	go build ./cmd/control-plane ./cmd/worker ./cmd/runner

run:
	go run ./cmd/control-plane

