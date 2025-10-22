# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nexus Auth is a Go-based authentication service for Bittensor's Nexus Framework. It acts as an Nginx auth_request endpoint that validates mTLS client certificates against public keys stored on-chain via the Pylon service.

## Architecture

The service validates client certificates through this flow:
1. Nginx terminates TLS and forwards client cert info via headers (especially `X-Client-Cert`)
2. Auth service extracts the SS58 address from the certificate's Organization (O) field
3. Service queries Pylon API to fetch the expected Ed25519 public key for that address
4. Service compares the certificate's public key against Pylon's response
5. Returns 200 (authorized) or 403 (forbidden)

Key components:
- `cmd/nexus-auth/main.go` - CLI entry point with two subcommands: `run` (starts server) and `generate` (creates client certs)
- `internal/auth/auth.go` - Core authentication logic and HTTP handler
- `internal/pylon/client.go` - HTTP client for Pylon API (`/api/v1/certificates`)
- `internal/configuration/configuration.go` - Config management (env vars + CLI flags)

## Development Commands

Build:
```bash
make build         # Builds binary to ./nexus-auth
make docker-build  # Builds Docker image
```

Code quality:
```bash
make deps          # Install golangci-lint v2.5.0
make format        # Run golangci-lint fmt and go mod tidy
make lint          # Check formatting, run go vet and golangci-lint
```

Testing:
```bash
go test -v ./...                    # Run all tests
go test -v ./internal/auth          # Run tests in specific package
make test                           # Same as go test -v ./...
make coverage                       # Generate coverage.html report
```

Running locally:
```bash
./nexus-auth run -listen-addr :8080 -pylon-endpoint http://localhost:8000
```

Generate client certificates:
```bash
./nexus-auth generate \
  -ss58-address YOUR_ADDRESS \
  -output-dir ./certs \
  -pylon-endpoint http://localhost:8000 \
  -not-after-days 3650 \
  -force-recreate
```

## Configuration

Configuration precedence: CLI flags > Environment variables > Defaults

Environment variables:
- `NEXUS_AUTH_LISTEN_ADDR` (default: `:8080`)
- `NEXUS_PYLON_ENDPOINT` (default: `http://pylon:8000`)

## Testing Patterns

- All test files use `_test.go` suffix
- Tests validate both success and error paths
- Mock Pylon responses using httptest for isolation
- Certificate parsing tests use real PEM-encoded test data

## Key Implementation Details

**Certificate Structure:**
- Self-signed X.509 certificates with Ed25519 keys
- SS58 address stored in Subject Organization field
- Client auth extended key usage

**Pylon API:**
- `GET /api/v1/certificates/{hotkey}` - Fetch public certificate data
- `GET /api/v1/certificates/self` - Fetch own certificate
- `POST /api/v1/certificates/self` - Generate new keypair (returns private key)

**Security:**
- Organization name sanitization prevents path traversal
- Only Ed25519 (algorithm=1) is supported
- Public key comparison is byte-by-byte

## Build Configuration

- Go version: 1.24+
- golangci-lint version pinned: v2.5.0
- Binary built with CGO_ENABLED=0 for static linking
- Build flags: `-a -installsuffix cgo`
- LDFLAGS: `-w -s` (strip debug info)
