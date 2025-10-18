# Nexus Auth

Authentication service for Bittensor's Nexus Framework.

## Architecture

This repository contains a Go-based Nexus Auth Service that can act as an Nginx auth_request endpoint to validate incoming requests. It verifies client certificates by retrieving and checking public key data via Pylon. The service can also be used to generate client certificates and, through Pylon, publish certificate information to the blockchain.

- Primary component: Nexus Auth Service (Go)
- Development helpers: Nginx reverse proxy and Docker Compose (development only)

For production, run the Go service behind your own ingress/reverse proxy as needed. Nginx and docker-compose provided here are for local development only.

## Features

- Nginx auth_request compatible endpoint: returns 200 (authorized) or 403 (forbidden)
- mTLS client certificate validation using Pylon-backed public keys (SS58 address stored in Organization field)
- Certificate generation helper: create client.key and client.crt; publish via Pylon to the blockchain
- Comprehensive logging for debugging and monitoring
- Simple configuration via environment variables or flags

## Quick Start

This section focuses on production usage.

### Configure the service

Set configuration via environment variables or flags:
- `NEXUS_AUTH_LISTEN_ADDR` (default: `:8080`)
- `NEXUS_PYLON_ENDPOINT` (default: `http://pylon:8000`)

### Running Auth Server


Use the run subcommand (default) to start the service.

Example:
```yaml
services:
  auth:
    image: backenddevelopersltd/nexus-auth:latest
    environment:
      NEXUS_AUTH_LISTEN_ADDR: ":8080"
      NEXUS_PYLON_ENDPOINT: "http://pylon:8000"
    volumes:
      - ./certs:/app/certs
    restart: unless-stopped
```

```bash
docker compose -p nexus up -d
```

### Generate a client key and certificate (via Pylon)

Use the generate subcommand to request a keypair from Pylon and create client.key and client.crt locally.
Pylon will handle publishing certificate data to the blockchain.

Example:
```bash
docker run --rm -it -v ./certs:/app/certs backenddevelopersltd/nexus-auth:latest generate \
  --pylon-endpoint YOUR_PYLON_ENDPOINT \
  --ss58-address YOUR_SS58_ADDRESS
```
Notes:
- `--not-after-days` can set the certificate validity in days. Default is 3650 (10 years).
- The SS58 address is stored in the certificate Subject Organization (O) field.

### Integrate with your reverse proxy

Configure your ingress/reverse proxy (e.g., Nginx/Envoy) to:
- Terminate TLS and enforce mTLS for client connections
- Call this service (GET /) as an auth_request or external authorization check
- Grant or deny the original request based on the 200/403 response

## Development

### Prerequisites

- Go 1.24+ installed
- Docker and Docker Compose
- Make

### Available Make Targets

```bash
make help
```

Common targets:
- `make all` - Full build pipeline (build, clean, format, lint, test)
- `make build` - Build the service as a binary
- `make build-docker` - Build the service as a docker image
- `make format` - Format the code
- `make lint` - Run linter
- `make test` - Run tests
- `make coverage` - Run tests with coverage report
- `make clean` - Clean build artifacts

## How It Works

1. **Client Request**: Client makes HTTPS request to nginx with client certificate
2. **SSL Termination**: Nginx handles SSL/TLS and extracts client certificate information
3. **Auth Request**: Nginx makes internal subrequest to auth service with certificate headers
4. **Certificate Validation**: Auth service validates certificate and checks against authorized certificates
5. **Response**: Auth service returns 200 (authorized) or 403 (unauthorized)
6. **Content Delivery**: Nginx serves protected content based on auth response

### Certificate Validation Process

1. Parse client certificate from `X-Client-Cert` header
2. Extract Organization Name (O) from the certificate subject (SS58 address)
3. Query Pylon for the expected public key using the Organization value as hotkey
4. Compare the certificate's public key with the public key returned by Pylon
5. Return validation result

## API Reference

### Auth Service Endpoints

- `GET /` - Health check and certificate validation endpoint

### Request Headers (from Nginx)

- `X-Client-Cert` - URL-escaped client certificate in PEM format
- `X-Client-Cert-Subject` - Client certificate subject DN
- `X-Client-Cert-Issuer` - Client certificate issuer DN
- `X-Original-URI` - Original request URI
- `X-Original-Method` - Original request method

### Response Codes

- **200 OK**: Certificate validation successful, access granted
- **403 Forbidden**: Certificate validation failed, access denied
  - No X-Client-Cert header provided
  - Invalid certificate format
  - No organization found in certificate
  - Organization not authorized (no matching certificate file)
  - Certificate public key doesn't match stored certificate's public key

## Project Structure

```
nexus-auth/
├── cmd/                     # Command-line sources
├── internal/                # Internal packages
│   ├── auth/                # Authentication logic
│   └── configuration/       # Configuration management
│   └── pylon/               # Pylon client
├── nginx/                   # Nginx config for local development only
├── Dockerfile               # Service container (optional)
├── Makefile                 # Build and development tools
├── docker-compose.yml       # Local development orchestration (dev-only)
└── go.mod                   # Go module definition
```
