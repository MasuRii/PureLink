BINARY_NAME=purelink
BUILD_DIR=bin
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -s -w"

.DEFAULT_GOAL := build

.PHONY: build test lint clean release install run

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/purelink

test:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

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
