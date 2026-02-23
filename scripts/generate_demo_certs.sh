#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

for generator in \
    "$ROOT_DIR/database_server/certs/generate_certs.sh" \
    "$ROOT_DIR/proxy_clone/certs/generate_certs.sh" \
    "$ROOT_DIR/nginx/certs/generate_certs.sh"
do
    if [[ ! -x "$generator" ]]; then
        chmod +x "$generator"
    fi
    "$generator"
done
