.PHONY: build clean test test-race test-coverage fmt lint dev-setup

build:
	@mkdir -p bin
	@go build -o bin/license-cli ./cmd/license-cli

test:
	@go test -v ./...

test-race:
	@go test -v -race ./...

test-coverage:
	@go test -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out

fmt:
	@go fmt ./...

lint:
	@PATH="$$PATH:$$HOME/go/bin" which golangci-lint > /dev/null 2>&1 && PATH="$$PATH:$$HOME/go/bin" golangci-lint run ./... || go vet ./...

clean:
	@rm -rf bin/ coverage.out test-keys/ *.key *.pem

dev-setup:
	@go mod download
	@go mod tidy
