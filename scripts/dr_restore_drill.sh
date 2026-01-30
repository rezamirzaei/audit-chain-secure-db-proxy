#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=== DR Restore Drill (Barman recover) ==="

if ! docker info > /dev/null 2>&1; then
  echo "ERROR: Docker is not running. Please start Docker Desktop."
  exit 1
fi

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

KEEP_RESTORED="${KEEP_RESTORED:-0}"

echo "Starting core services (postgres + redis + database-server + barman)..."
"${COMPOSE[@]}" up -d postgres redis database-server barman

echo "Waiting for Postgres..."
for _ in {1..60}; do
  if "${COMPOSE[@]}" exec -T postgres pg_isready -U postgres -d appdb > /dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "Validating Barman configuration..."
"${COMPOSE[@]}" exec -T barman barman check main > /dev/null

echo "Waiting for database-server to initialize schema..."
for _ in {1..60}; do
  if curl -k -s https://localhost:5002/api/health | grep -q '"healthy"'; then
    break
  fi
  sleep 1
done

ts="$(date -u +%Y%m%dT%H%M%SZ)"
restore_point="dr_restore_point_${ts}"
marker_name="dr_after_${ts}"

echo "Taking base backup..."
"${COMPOSE[@]}" exec -T barman barman backup main > /dev/null
backup_id="$(
  "${COMPOSE[@]}" exec -T barman barman list-backups --minimal main \
    | python3 -c "import sys; lines=[l.strip() for l in sys.stdin if l.strip()]; print(lines[0] if lines else '')"
)"
if [[ -z "${backup_id}" ]]; then
  echo "ERROR: Could not determine latest backup id"
  exit 1
fi
echo "Backup id: ${backup_id}"

echo "Creating restore point: ${restore_point}"
"${COMPOSE[@]}" exec -T postgres psql -U postgres -d appdb -c "SELECT pg_create_restore_point('${restore_point}');" > /dev/null

echo "Writing marker row AFTER restore point (should NOT exist after recovery): ${marker_name}"
"${COMPOSE[@]}" exec -T postgres psql -U postgres -d appdb -c "INSERT INTO departments (name, budget) VALUES ('${marker_name}', 1.0);" > /dev/null

echo "Forcing WAL switch..."
"${COMPOSE[@]}" exec -T postgres psql -U postgres -d appdb -c "SELECT pg_switch_wal();" > /dev/null

echo "Letting Barman ingest WAL..."
for _ in {1..10}; do
  "${COMPOSE[@]}" exec -T barman barman cron > /dev/null 2>&1 || true
  sleep 2
done

dest="/var/lib/barman/recoveries/${backup_id}_${restore_point}"
echo "Recovering to restore point into: ${dest}"
"${COMPOSE[@]}" exec -T barman bash -lc "rm -rf '${dest}'"
"${COMPOSE[@]}" exec -T barman barman recover --target-name "${restore_point}" --target-action promote main "${backup_id}" "${dest}" > /dev/null

echo "Fixing recovered data directory ownership for Postgres (uid 70)..."
"${COMPOSE[@]}" exec -T barman chown -R 70:70 "${dest}"

echo "Allowing Postgres to traverse the Barman volume (execute-only)..."
"${COMPOSE[@]}" exec -T barman chmod 0711 /var/lib/barman
"${COMPOSE[@]}" exec -T barman chmod 0755 /var/lib/barman/recoveries

echo "Starting restored Postgres instance on localhost:55432..."
barman_cid="$("${COMPOSE[@]}" ps -q barman)"
barman_volume="$(docker inspect "${barman_cid}" --format '{{ range .Mounts }}{{ if eq .Destination "/var/lib/barman" }}{{ .Name }}{{ end }}{{ end }}')"
if [[ -z "${barman_volume}" ]]; then
  echo "ERROR: Could not detect barman volume name"
  exit 1
fi

restored_container="dr-postgres-restored-${ts}"
cleanup() {
  if [[ "${KEEP_RESTORED}" == "1" ]]; then
    return 0
  fi
  docker rm -f "${restored_container}" > /dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "${restored_container}" \
  -p 55432:5432 \
  -e PGDATA="${dest}" \
  -e POSTGRES_PASSWORD=postgres \
  -v "${barman_volume}:/var/lib/barman" \
  -v "${ROOT_DIR}/postgres/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro" \
  postgres:15-alpine \
  postgres -c hba_file=/etc/postgresql/pg_hba.conf > /dev/null

echo "Waiting for restored Postgres..."
for _ in {1..60}; do
  if [[ "$(docker inspect -f '{{.State.Running}}' "${restored_container}" 2>/dev/null || echo false)" != "true" ]]; then
    echo "ERROR: Restored Postgres container exited early. Logs:"
    docker logs "${restored_container}" 2>&1 | tail -n 200 || true
    exit 1
  fi
  if docker exec "${restored_container}" pg_isready -U postgres -d appdb > /dev/null 2>&1; then
    break
  fi
  sleep 1
done

count="$(docker exec "${restored_container}" psql -U postgres -d appdb -tAc "SELECT COUNT(*) FROM departments WHERE name='${marker_name}';" | tr -d '[:space:]')"
if [[ "${count}" != "0" ]]; then
  echo "ERROR: Restore drill failed; marker row exists in recovered DB (count=${count})"
  exit 1
fi

echo "SUCCESS: Restore drill passed; marker row is absent after recovery to restore point."
if [[ "${KEEP_RESTORED}" == "1" ]]; then
  echo "Restored Postgres is running at localhost:55432 (container: ${restored_container})"
else
  echo "Restored Postgres container will be removed automatically (set KEEP_RESTORED=1 to keep it)."
fi
