#!/bin/bash
# Test script to verify the setup

echo "=== Testing Database Server & Proxy Clone Setup ==="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running. Please start Docker Desktop."
    exit 1
fi

echo "✓ Docker is running"

# Navigate to project directory
cd "$(dirname "$0")"

# Stop any existing containers
echo "Stopping existing containers..."
docker-compose down --remove-orphans 2>/dev/null

# Build containers
echo "Building containers..."
docker-compose build

# Start containers
echo "Starting containers..."
docker-compose up -d

# Wait for containers to start
echo "Waiting for containers to start..."
sleep 5

# Check container status
echo ""
echo "=== Container Status ==="
docker-compose ps

# Test database server (HTTPS)
echo ""
echo "=== Testing Database Server (HTTPS) ==="
curl -k -s https://localhost:5002/api/health | head -100

# Test proxy
echo ""
echo "=== Testing Proxy ==="
curl -k -s https://localhost:8080/api/status | head -100

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
