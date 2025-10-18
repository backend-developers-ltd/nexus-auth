# Nexus Auth

Authentication service for Bittensor's Nexus Framework.

## Architecture

This repository contains a single Go-based Nexus Auth Service that performs mTLS certificate validation.

- Primary component: Nexus Auth Service (Go)
- Development helpers: Nginx reverse proxy and Docker Compose (development only)

For local development, Nginx can be used as a TLS termination and reverse proxy with auth_request integration via docker-compose. In production, run the Go service directly behind your own ingress/reverse proxy as needed.

## Features

- **Containerized Development Environment**: Docker Compose and Nginx provided for local development only
- **mTLS Certificate Validation**: Validates client certificates with organization-based authentication
- **SSL/TLS Termination (dev-only)**: Nginx handles HTTPS with automatic HTTP to HTTPS redirection in local development
- **Certificate Verification**: Compares certificates against stored authorized certificates
- **Comprehensive Logging**: Detailed request and validation logging for debugging and monitoring
- **Development Tools**: Complete Makefile with testing, linting, and coverage support

## Quick Start

### Prerequisites

- Go 1.24+ installed
- Certificate files for authorized organizations (placed in `certs/`)
- Optional (for development): Docker and Docker Compose

### Run the Auth Service directly (recommended for production)

1. Build and run:
   ```bash
   make build
   ./nexus-auth
   ```
   Or run without building:
   ```bash
   go run ./
   ```

2. Configure via environment variables or flags:
   - NEXUS_LISTEN_ADDR (default: ":8080")
   - NEXUS_CERTS_DIR (default: "certs")

### Development with Docker Compose (includes Nginx proxy)

1. Start services:
   ```bash
   docker-compose up -d
   ```

2. Access via Nginx (development only):
   - HTTPS: https://localhost:443
   - HTTP:  http://localhost:80 (redirects to HTTPS)

3. Stop services:
   ```bash
   docker-compose down
   ```

## Configuration

### Certificate Setup

Place client certificate files in the `certs/` directory, named after the organization:

```bash
# Example: For organization "ExampleCorp", create:
certs/ExampleCorp.crt
```

Certificate files should be in PEM format:
```
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END CERTIFICATE-----
```

### Environment Variables

The auth service supports the following environment variables:
- `NEXUS_LISTEN_ADDR`: Listen address for the auth service (default: ":8080")
- `NEXUS_CERTS_DIR`: Directory containing certificate files (default: "certs")

### Command Line Options

The auth service also supports command line flags:
- `-listen-addr`: Address to listen on (default: ":8080")
- `-certs-dir`: Directory containing certificate files (default: "certs")

## Development

### Building the Auth Service

```bash
make build
```

### Available Make Targets

```bash
make help
```

Common targets:
- `make all` - Full build pipeline (clean, format, lint, vet, test, build)
- `make dev` - Quick development cycle (format, vet, test, build)
- `make test` - Run tests
- `make coverage` - Run tests with coverage report
- `make lint` - Run linter
- `make clean` - Clean build artifacts

### Running Tests

```bash
make test
```

### Running Locally (Development)

```bash
go run ./
```

## How It Works (with Nginx in development)

1. **Client Request**: Client makes HTTPS request to nginx with client certificate
2. **SSL Termination**: Nginx handles SSL/TLS and extracts client certificate information
3. **Auth Request**: Nginx makes internal subrequest to auth service with certificate headers
4. **Certificate Validation**: Auth service validates certificate and checks against authorized certificates
5. **Response**: Auth service returns 200 (authorized) or 403 (unauthorized)
6. **Content Delivery**: Nginx serves protected content based on auth response

### Certificate Validation Process

1. Parse client certificate from `X-Client-Cert` header
2. Extract Organization Name (O) from certificate subject
3. Load corresponding certificate from `certs/{OrganizationName}.crt`
4. Compare certificate's public key with stored certificate's public key
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
├── internal/                # Internal packages
│   ├── auth/                # Authentication logic
│   └── configuration/       # Configuration management
├── certs/                   # Authorized client certificates (PEM)
├── nginx/                   # Nginx config for local development only
│   ├── conf.d/
│   └── ssl/
├── scripts/                 # Helper scripts (e.g., certificate generation)
├── Dockerfile               # Service container (optional)
├── Makefile                 # Build and development tools
├── docker-compose.yml       # Local development orchestration (dev-only)
├── go.mod                   # Go module definition
└── main.go                  # Application entry point
```

## Security Considerations

- The auth service runs as a non-root user in the container
- Client certificates are validated against pre-authorized certificates
- HTTPS redirection and TLS termination are handled by Nginx only in the development setup
- When using docker-compose, the auth service is only accessible internally via the Docker network

## Troubleshooting

Note: The following items refer to the docker-compose development environment.

### Common Issues

1. **Certificate validation fails**: Check that the certificate file exists in `certs/` directory with the correct organization name
2. **SSL errors**: Verify SSL certificates are properly placed in `nginx/ssl/`
3. **Service not accessible**: Ensure Docker containers are running with `docker-compose ps`

### Logs

View service logs:
```bash
# All services
docker-compose logs

# Auth service only
docker-compose logs auth

# Nginx only
docker-compose logs nginx
```
