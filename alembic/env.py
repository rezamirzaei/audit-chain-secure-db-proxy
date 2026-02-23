from __future__ import annotations

import os
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def default_sqlite_url() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    sqlite_path = repo_root / "database_server" / "data" / "database.db"
    return f"sqlite:///{sqlite_path}"


def resolve_database_url() -> str:
    url = (
        os.environ.get("ALEMBIC_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
        or os.environ.get("POSTGRES_DSN")
    )
    if url:
        return url

    sqlite_path_env = os.environ.get("SQLITE_DB_PATH")
    if sqlite_path_env:
        return f"sqlite:///{Path(sqlite_path_env).expanduser()}"

    return default_sqlite_url()


config.set_main_option("sqlalchemy.url", resolve_database_url())


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
