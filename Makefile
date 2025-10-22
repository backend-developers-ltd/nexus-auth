# Project
BINARY_NAME=nexus-auth
DOCKER_NAME=backenddevelopersltd/nexus-auth
DOCKER_TAG=latest

# Build flags
BUILD_FLAGS=-a -installsuffix cgo
LDFLAGS=-w -s

# Dev Tools
GOLANGCI_LINT_VER=2.5.0

.PHONY: all deps build docker-build clean format lint test coverage mod-tidy mod-verify help

all: clean format lint test build

deps:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v${GOLANGCI_LINT_VER}

build:
	CGO_ENABLED=0 GOOS=linux go build $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/nexus-auth

docker-build:
	docker build -t ${DOCKER_NAME}:${DOCKER_TAG} -f Dockerfile .

clean:
	go clean
	rm -f $(BINARY_NAME) coverage.html coverage.out

format: deps
	golangci-lint fmt ./...
	go mod tidy

lint: deps
	golangci-lint fmt --diff ./...
	go vet ./...
	golangci-lint run

test:
	go test -v ./...

coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

mod-tidy:
	go mod tidy

mod-verify:
	go mod verify

help:
	@echo "Available targets:"
	@echo "  all          - Run clean, format, lint, vet, test, and build"
	@echo "  deps         - Install dependencies"
	@echo "  build        - Build the binary"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  coverage     - Run tests with coverage report"
	@echo "  format       - Format code and tidy modules"
	@echo "  lint         - Run linter"
	@echo "  mod-tidy     - Tidy modules"
	@echo "  mod-verify   - Verify modules"
	@echo "  help         - Show this help message"
