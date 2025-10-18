# Build stage
FROM golang:1.24.1-alpine AS builder

# Install make for Makefile support
RUN apk add --no-cache make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod ./

# Download dependencies (if any)
RUN go mod download

# Copy source code
COPY . .

# Build the application using Makefile
RUN make build

# Runtime stage
FROM alpine:latest

# Install ca-certificates for TLS
RUN apk --no-cache add ca-certificates

# Create a non-root user
RUN addgroup -g 1000 -S nexus && \
    adduser -u 1000 -S nexus -G nexus

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/nexus-auth /usr/bin/

# Change ownership to non-root user
RUN chown -R nexus:nexus /app

# Switch to non-root user
USER nexus

# Expose the default port
EXPOSE 8080

# Run the application
ENTRYPOINT ["nexus-auth"]
CMD ["run"]
