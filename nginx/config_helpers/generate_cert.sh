#!/bin/sh

# TODO(maciek): Change it for production, based on the bittensor topology and requirements

# Check if the certificate and key already exist
if [ ! -f "/etc/nginx/ssl/nginx.crt" ] || [ ! -f "/etc/nginx/ssl/nginx.key" ]; then
    if ! command -v openssl >/dev/null 2>&1; then
        echo "OpenSSL not found. Installing it..."
        apk --no-cache add openssl
        if [ $? -ne 0 ]; then
            echo "Failed to install OpenSSL. Exiting."
            exit 1
        fi
    else
        echo "OpenSSL is already installed."
    fi

    echo "Generating self-signed certificates..."
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt -subj "/CN=localhost"
    if [ $? -eq 0 ]; then
        echo "Self-signed certificates generated successfully."
    else
        echo "Failed to generate self-signed certificates. Exiting."
        exit 1
    fi
else
    echo "Certificates already exist. Skipping generation."
fi
