# Paman Password Manager - Makefile

.PHONY: all build test clean help install fmt lint vet run

# Default target
all: fmt build

# Build the binary
build:
	@echo "Building paman..."
	go build -tags sqlite_fts5 -o bin/paman ./cmd/paman

# Run all tests
test:
	@echo "Running tests..."
	go test ./pkg/config/... ./internal/models/... ./internal/crypto/... -v

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test ./pkg/config/... ./internal/models/... ./internal/crypto/... -cover

# Run database tests (requires FTS5)
test-db:
	@echo "Running database tests (requires FTS5)..."
	go test -tags sqlite_fts5 ./internal/infrastructure/persistence/sqlite/... -v

# Format all Go files
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run ./...

# Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

# Install the binary to /usr/local/bin
install: build
	@echo "Installing to /usr/local/bin..."
	sudo cp bin/paman /usr/local/bin/paman
	@echo "✓ Installed! You can now run 'paman' from anywhere"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f bin/paman
	rm -f paman
	@echo "✓ Clean"

# Show help
help:
	@echo "Paman Password Manager - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Format, build, and test (default)"
	@echo "  build         - Build the binary"
	@echo "  test          - Run unit tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  test-db        - Run database tests (requires FTS5)"
	@echo "  fmt           - Format all Go code"
	@echo "  lint          - Run linter"
	@echo "  vet           - Run go vet"
	@echo "  install       - Install to /usr/local/bin"
	@echo "  clean         - Remove build artifacts"
	@echo "  help          - Show this help message"

# Development workflow
dev: fmt vet build test

# Quick test during development
quick-test:
	@echo "Quick test (no verbose output)..."
	go test ./pkg/config/... ./internal/models/... ./internal/crypto/...

# Run all tests (including database if available)
test-all: test
	@echo "Note: Database tests require FTS5 support. Use 'make test-db' to run them."
