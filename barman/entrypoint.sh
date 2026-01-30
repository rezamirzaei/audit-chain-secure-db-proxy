#!/usr/bin/env bash
set -euo pipefail

SERVER_NAME="${BARMAN_SERVER_NAME:-main}"
PG_HOST="${BARMAN_PG_HOST:-postgres}"
PG_PORT="${BARMAN_PG_PORT:-5432}"
PG_DBNAME="${BARMAN_PG_DBNAME:-appdb}"
PG_USER="${BARMAN_PG_USER:-barman}"
PG_PASSWORD="${BARMAN_PG_PASSWORD:-}"
RETENTION_POLICY="${BARMAN_RETENTION_POLICY:-RECOVERY WINDOW OF 7 DAYS}"
SLOT_NAME="${BARMAN_SLOT_NAME:-barman}"

if [[ -z "${PG_PASSWORD}" ]]; then
  echo "BARMAN_PG_PASSWORD is required" >&2
  exit 2
fi

mkdir -p /var/lib/barman /var/log/barman
chown -R barman:barman /var/lib/barman /var/log/barman

mkdir -p /wal_archive
chmod 0777 /wal_archive

cat > /etc/barman.conf <<EOF
[barman]
barman_home = /var/lib/barman
log_file = /var/log/barman/barman.log
compression = gzip

[${SERVER_NAME}]
description = "PostgreSQL primary (docker-compose)"
conninfo = host=${PG_HOST} port=${PG_PORT} user=${PG_USER} dbname=${PG_DBNAME} password=${PG_PASSWORD}
streaming_conninfo = host=${PG_HOST} port=${PG_PORT} user=${PG_USER} dbname=${PG_DBNAME} password=${PG_PASSWORD}
backup_method = postgres
archiver = on
streaming_archiver = on
incoming_wals_directory = /wal_archive
slot_name = ${SLOT_NAME}
create_slot = auto
retention_policy = ${RETENTION_POLICY}
wal_retention_policy = main
EOF

chown barman:barman /etc/barman.conf
chmod 600 /etc/barman.conf

if [[ "${1:-}" == "cron-loop" ]]; then
  exec su -s /bin/bash barman -c "barman receive-wal --create-slot ${SERVER_NAME} || true; while true; do barman cron; sleep 60; done"
fi

cmd="$(printf '%q ' "$@")"
exec su -s /bin/bash barman -c "${cmd}"
