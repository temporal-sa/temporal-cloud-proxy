BINARY_NAME := tclp
CMD_DIR := ./cmd
OUTPUT_DIR := .
OUTPUT_PATH := $(OUTPUT_DIR)/$(BINARY_NAME)

.PHONY: all build clean test test-verbose test-coverage test-race test-short test-clean benchmark test-auth test-crypto test-proxy test-utils

all: test build

build:
	go build -o $(OUTPUT_PATH) $(CMD_DIR)

clean:
	rm -f $(OUTPUT_PATH)

# Test targets
test:
	go test ./...

test-verbose:
	go test -v ./...

test-coverage:
	go test -cover ./...

test-race:
	go test -race ./...

test-short:
	go test -short ./...

test-clean:
	go clean -testcache

benchmark:
	go test -bench=. ./...

# Package-specific test targets
test-auth:
	go test ./auth/...

test-crypto:
	go test ./crypto/...

test-proxy:
	go test ./proxy/...

test-utils:
	go test ./utils/...
