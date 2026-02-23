#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE=()
if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
elif docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
else
  echo "ERROR: Docker Compose not found."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running."
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "ERROR: npm is not installed."
  exit 1
fi

cleanup() {
  if [[ "${KEEP_E2E_CONTAINERS:-false}" != "true" ]]; then
    "${COMPOSE[@]}" down --remove-orphans -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Ensuring demo TLS certificates..."
bash scripts/generate_demo_certs.sh

echo "Starting Docker stack for E2E..."
"${COMPOSE[@]}" down --remove-orphans -v >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build

wait_for_url() {
  local url="$1"
  local name="$2"
  for _ in $(seq 1 60); do
    if curl -kfsS "$url" >/dev/null 2>&1; then
      echo "✓ $name is ready"
      return 0
    fi
    sleep 2
  done
  echo "ERROR: $name did not become ready: $url"
  return 1
}

wait_for_url "${DB_BASE_URL:-https://localhost:5002}/api/health" "database server"
wait_for_url "${PROXY_BASE_URL:-https://localhost:8080}/api/health" "proxy clone"

echo "Installing Playwright dependencies..."
npm --prefix e2e install
npx --prefix e2e playwright install --with-deps chromium

echo "Running browser E2E tests..."
npx --prefix e2e playwright test
