#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Cleaning local caches (safe to delete, not committed)..."

rm -rf .pytest_cache .mypy_cache .ruff_cache

find database_server proxy_clone shared tests \
  -name "__pycache__" -type d -prune -exec rm -rf '{}' +

find database_server proxy_clone shared tests \
  -name "*.pyc" -type f -delete

echo "Done."

