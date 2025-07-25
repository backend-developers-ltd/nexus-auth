# Bittensor Nexus

Next generation, containerized, Bittensor's subnet template.

## Architecture

The system consists of two main components:

- **Auth Service**: A Go-based mTLS certificate validation service
- **Nginx Proxy**: SSL/TLS termination and reverse proxy with auth_request integration

Both services run in Docker containers and communicate over a private network.

## Features

- **Containerized Deployment**: Complete Docker Compose setup for easy deployment
- **mTLS Certificate Validation**: Validates client certificates with organization-based authentication
- **SSL/TLS Termination**: Nginx handles HTTPS with automatic HTTP to HTTPS redirection
- **Certificate Verification**: Compares certificates against stored authorized certificates
- **Comprehensive Logging**: Detailed request and validation logging for debugging and monitoring
- **Development Tools**: Complete Makefile with testing, linting, and coverage support

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Certificate files for authorized organizations (placed in `certs/`)

### Running the System

1. **Start the services:**
   ```bash
   docker-compose up -d
   ```

2. **Access the system:**
   - HTTPS: `https://localhost:443`
   - HTTP (redirects to HTTPS): `http://localhost:80`

3. **Stop the services:**
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
cd auth
make build
```

### Available Make Targets

```bash
cd auth
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
cd auth
make test
```

### Running Locally (Development)

```bash
cd auth
go run main.go
```

## How It Works

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
bittensor-nexus/
├── auth/                    # Go authentication service
│   ├── internal/           # Internal packages
│   │   ├── auth/          # Authentication logic
│   │   └── configuration/ # Configuration management
│   ├── Dockerfile         # Auth service container
│   ├── Makefile          # Build and development tools
│   └── main.go           # Application entry point
├── nginx/                 # Nginx configuration
│   ├── conf.d/           # Nginx site configuration
│   └── ssl/              # SSL certificates
├── certs/                # Authorized certificates
└── docker-compose.yml   # Container orchestration
```

## Security Considerations

- The auth service runs as a non-root user in the container
- Client certificates are validated against pre-authorized certificates
- All HTTP traffic is automatically redirected to HTTPS
- The auth service is only accessible internally via Docker network

## Troubleshooting

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
