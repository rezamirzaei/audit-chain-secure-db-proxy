#!/bin/bash
# Test script to verify the setup
set -euo pipefail

echo "=== Testing Database Server & Proxy Clone Setup ==="

POSTGRES_USER="${POSTGRES_USER:-postgres}"
APP_DB_NAME="${APP_DB_NAME:-appdb}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running. Please start Docker Desktop."
    exit 1
fi

echo "✓ Docker is running"

# Detect Docker Compose command (v1 `docker-compose` or v2 `docker compose`)
COMPOSE=()
if command -v docker-compose > /dev/null 2>&1; then
    COMPOSE=(docker-compose)
elif docker compose version > /dev/null 2>&1; then
    COMPOSE=(docker compose)
else
    echo "ERROR: Docker Compose not found. Install Docker Desktop or docker-compose."
    exit 1
fi

# Navigate to project directory
cd "$(dirname "$0")"

echo "Ensuring local demo TLS certificates exist..."
bash scripts/generate_demo_certs.sh

# Stop any existing containers
echo "Stopping existing containers..."
"${COMPOSE[@]}" down --remove-orphans -v 2>/dev/null

# Build containers
echo "Building containers..."
"${COMPOSE[@]}" build

# Start containers
echo "Starting containers..."
"${COMPOSE[@]}" up -d

# Wait for containers to start
echo "Waiting for containers to start..."
sleep 5

# Wait for Postgres
echo ""
echo "Waiting for Postgres to be ready..."
POSTGRES_READY=0
for i in {1..30}; do
    if "${COMPOSE[@]}" exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$APP_DB_NAME" > /dev/null 2>&1; then
        echo "✓ Postgres is ready"
        POSTGRES_READY=1
        break
    fi
    sleep 1
done

if [ "$POSTGRES_READY" -ne 1 ]; then
    echo "ERROR: Postgres did not become ready"
    echo ""
    echo "=== Postgres Logs ==="
    "${COMPOSE[@]}" logs postgres || true
    echo ""
    echo "=== Database Server Logs ==="
    "${COMPOSE[@]}" logs database-server || true
    exit 1
fi

# Check container status
echo ""
echo "=== Container Status ==="
"${COMPOSE[@]}" ps

if ! "${COMPOSE[@]}" ps --services --filter status=running | grep -q '^database-server$'; then
    echo "ERROR: database-server is not running"
    echo ""
    echo "=== Database Server Logs ==="
    "${COMPOSE[@]}" logs database-server || true
    exit 1
fi

# Test database server (HTTPS)
echo ""
echo "=== Testing Database Server (HTTPS) ==="
curl -k -s https://localhost:5002/api/health | head -100

# Test proxy
echo ""
echo "=== Testing Proxy ==="
curl -k -s https://localhost:8080/api/health | head -100

echo ""
echo "=== Testing Barman (Disaster Recovery) ==="
echo "Forcing WAL switch to validate archiving..."
"${COMPOSE[@]}" exec -T postgres psql -U "$POSTGRES_USER" -d "$APP_DB_NAME" -c "SELECT pg_switch_wal();" > /dev/null

echo "Waiting for Barman to ingest at least one WAL..."
for i in {1..30}; do
    if "${COMPOSE[@]}" exec -T barman barman check main > /dev/null 2>&1; then
        break
    fi
    "${COMPOSE[@]}" exec -T barman barman cron > /dev/null 2>&1 || true
    sleep 2
done

"${COMPOSE[@]}" exec -T barman barman check main
"${COMPOSE[@]}" exec -T barman barman backup main
"${COMPOSE[@]}" exec -T barman barman list-backup main | head -100

echo ""
echo "=== Setup Complete ==="
echo "Database Server (HTTPS): https://localhost:5002"
echo "Proxy Clone (HTTPS):     https://localhost:8080"
echo ""
echo "Default Credentials:"
echo "  admin / SecurePass123! (Security answer: blue)"
echo "  analyst / AnalystPass456! (Security answer: fluffy)"
echo ""
echo "Check TOTP codes in container logs:"
echo "  docker-compose logs database-server | grep 'TOTP'"
