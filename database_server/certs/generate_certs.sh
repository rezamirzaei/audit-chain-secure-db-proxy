#!/bin/bash
set -euo pipefail

# Generate self-signed SSL certificate for the database server (demo/dev only)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -f cert.pem && -f key.pem ]]; then
    echo "database_server certs already exist"
    exit 0
fi

openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -keyout key.pem \
    -out cert.pem \
    -subj "/C=US/ST=State/L=City/O=DataVault/OU=IT/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:database-server"

echo "Generated database_server demo TLS certs"
