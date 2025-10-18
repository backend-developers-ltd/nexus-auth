# Service
BINARY_NAME=nexus-auth
DOCKER_NAME=nexus-auth
DOCKER_TAG=latest

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet

# Build flags
BUILD_FLAGS=-a -installsuffix cgo
LDFLAGS=-w -s

# Linter
GOLANGCI_LINT=golangci-lint

.PHONY: all build docker-build clean format lint test coverage mod-tidy mod-verify help

# Default target
all: clean format lint test build

# Build the binary
build:
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

# Build docker image
docker-build:
	docker build -t ${DOCKER_NAME}:${DOCKER_TAG} -f Dockerfile .

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME) coverage.html coverage.out

# Format code
format:
	$(GOFMT) -s -w .
	$(GOCMD) mod tidy

# Lint code
lint: install-golangci-lint
	$(GOVET) ./...
	$(GOLANGCI_LINT) run

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Tidy modules
mod-tidy:
	$(GOMOD) tidy

# Verify modules
mod-verify:
	$(GOMOD) verify

# Install golangci-lint
install-golangci-lint:
	@which $(GOLANGCI_LINT) > /dev/null || (echo "Installing golangci-lint..." && \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin)

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
	@echo "  help         - Show this help message"
