# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet

# Binary name
BINARY_NAME=nexus-auth

# Build flags
BUILD_FLAGS=-a -installsuffix cgo
LDFLAGS=-w -s

# Linter
GOLANGCI_LINT=golangci-lint

.PHONY: all build clean test coverage lint format vet help install-tools mod-tidy mod-verify

# Default target
all: clean format lint vet test build

# Build the binary
build:
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME) coverage.html coverage.out

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Format code
format:
	$(GOFMT) -s -w .
	$(GOCMD) mod tidy

# Lint code
lint: install-golangci-lint
	$(GOLANGCI_LINT) run

# Vet code
vet:
	$(GOVET) ./...

# Tidy modules
mod-tidy:
	$(GOMOD) tidy

# Verify modules
mod-verify:
	$(GOMOD) verify

# Install development tools
install-tools: install-golangci-lint

# Install golangci-lint
install-golangci-lint:
	@which $(GOLANGCI_LINT) > /dev/null || (echo "Installing golangci-lint..." && \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin)

# Run a quick development cycle
dev: format vet test build

# Docker build (for use in Dockerfile)
docker-build: format vet build

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Run clean, format, lint, vet, test, and build"
	@echo "  build        - Build the binary"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  coverage     - Run tests with coverage report"
	@echo "  format       - Format code and tidy modules"
	@echo "  lint         - Run linter"
	@echo "  vet          - Run go vet"
	@echo "  mod-tidy     - Tidy modules"
	@echo "  mod-verify   - Verify modules"
	@echo "  install-tools- Install development tools"
	@echo "  dev          - Quick development cycle (format, vet, test, build)"
	@echo "  docker-build - Build for Docker (format, vet, build)"
	@echo "  help         - Show this help message"
