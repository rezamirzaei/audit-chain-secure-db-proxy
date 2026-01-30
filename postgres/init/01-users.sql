-- Create application + replication roles for the demo stack.
DO
$$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app') THEN
        CREATE ROLE app LOGIN PASSWORD 'app_password';
    END IF;

    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'barman') THEN
        CREATE ROLE barman LOGIN REPLICATION PASSWORD 'barman_password';
    END IF;
END
$$;

GRANT ALL PRIVILEGES ON DATABASE appdb TO app;
GRANT USAGE, CREATE ON SCHEMA public TO app;
GRANT CONNECT ON DATABASE appdb TO barman;

-- Required for `barman check` (PostgreSQL 15+ backup functions).
GRANT EXECUTE ON FUNCTION pg_catalog.pg_backup_start(text, boolean) TO barman;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_backup_stop(boolean) TO barman;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_switch_wal() TO barman;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_create_restore_point(text) TO barman;
GRANT pg_monitor TO barman;
