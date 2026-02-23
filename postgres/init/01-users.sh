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
DO
$$
DECLARE
    app_user text := :'app_db_user';
    app_password text := :'app_db_password';
    barman_user text := :'barman_db_user';
    barman_password text := :'barman_db_password';
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = app_user) THEN
        EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', app_user, app_password);
    END IF;

    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = barman_user) THEN
        EXECUTE format('CREATE ROLE %I LOGIN REPLICATION PASSWORD %L', barman_user, barman_password);
    END IF;
END
$$;

DO
$$
DECLARE
    app_db_name text := :'app_db_name';
    app_user text := :'app_db_user';
    barman_user text := :'barman_db_user';
BEGIN
    EXECUTE format('GRANT ALL PRIVILEGES ON DATABASE %I TO %I', app_db_name, app_user);
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', app_db_name, barman_user);
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO :"app_db_user";

-- Required for `barman check` (PostgreSQL 15+ backup functions).
GRANT EXECUTE ON FUNCTION pg_catalog.pg_backup_start(text, boolean) TO :"barman_db_user";
GRANT EXECUTE ON FUNCTION pg_catalog.pg_backup_stop(boolean) TO :"barman_db_user";
GRANT EXECUTE ON FUNCTION pg_catalog.pg_switch_wal() TO :"barman_db_user";
GRANT EXECUTE ON FUNCTION pg_catalog.pg_create_restore_point(text) TO :"barman_db_user";
GRANT pg_monitor TO :"barman_db_user";
SQL
