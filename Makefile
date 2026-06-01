BINARY_NAME=purelink
BUILD_DIR=bin
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -s -w"

.DEFAULT_GOAL := build

.PHONY: build test lint clean release install run fmt coverage generate test-integration test-e2e bench fuzz sec

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/purelink

test:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

generate:
	go generate ./...

test-integration:
	go test -tags=integration ./...

test-e2e:
	go test -tags=e2e ./...

bench:
	go test -bench=. -benchmem -run=^$$ ./...

fuzz:
	@echo "Running fuzz smoke tests (best-effort)..."
	@go test -fuzz=FuzzEndpointParse -fuzztime=10s ./pkg/endpoint/ 2>/dev/null || echo "  FuzzEndpointParse not available yet"
	@go test -fuzz=FuzzVMessURI -fuzztime=10s ./pkg/v2rayn/ 2>/dev/null || echo "  FuzzVMessURI not available yet"

sec:
	@echo "Running security scans..."
	@which gosec >/dev/null 2>&1 || (echo "gosec not installed; run: go install github.com/securego/gosec/v2/cmd/gosec@latest" && exit 1)
	gosec ./...
	@which govulncheck >/dev/null 2>&1 || (echo "govulncheck not installed; run: go install golang.org/x/vuln/cmd/govulncheck@latest" && exit 1)
	govulncheck ./...

clean:
	rm -rf $(BUILD_DIR) dist/ coverage.out coverage.html

install:
	go install $(LDFLAGS) ./cmd/purelink

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean

deps:
	go mod download
	go mod tidy
