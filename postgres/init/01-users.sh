#!/bin/sh
set -eu

: "${APP_DB_NAME:?APP_DB_NAME is required}"
: "${APP_DB_USER:?APP_DB_USER is required}"
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD is required}"
: "${BARMAN_DB_USER:?BARMAN_DB_USER is required}"
: "${BARMAN_DB_PASSWORD:?BARMAN_DB_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  -v app_db_name="$APP_DB_NAME" \
  -v app_db_user="$APP_DB_USER" \
  -v app_db_password="$APP_DB_PASSWORD" \
  -v barman_db_user="$BARMAN_DB_USER" \
  -v barman_db_password="$BARMAN_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'app_db_user', :'app_db_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_db_user')
\gexec

SELECT format('CREATE ROLE %I LOGIN REPLICATION PASSWORD %L', :'barman_db_user', :'barman_db_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'barman_db_user')
\gexec

SELECT format('GRANT ALL PRIVILEGES ON DATABASE %I TO %I', :'app_db_name', :'app_db_user')
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'app_db_name', :'barman_db_user')
\gexec

SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'app_db_user')
\gexec

-- Required for `barman check` (PostgreSQL 15+ backup functions).
SELECT format('GRANT EXECUTE ON FUNCTION pg_catalog.pg_backup_start(text, boolean) TO %I', :'barman_db_user')
\gexec
SELECT format('GRANT EXECUTE ON FUNCTION pg_catalog.pg_backup_stop(boolean) TO %I', :'barman_db_user')
\gexec
SELECT format('GRANT EXECUTE ON FUNCTION pg_catalog.pg_switch_wal() TO %I', :'barman_db_user')
\gexec
SELECT format('GRANT EXECUTE ON FUNCTION pg_catalog.pg_create_restore_point(text) TO %I', :'barman_db_user')
\gexec
SELECT format('GRANT pg_monitor TO %I', :'barman_db_user')
\gexec
SQL
