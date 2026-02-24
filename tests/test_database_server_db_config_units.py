from __future__ import annotations

from pathlib import Path

import pytest

from database_server.db_config import load_db_config_from_env, sqlite_db_path_for_runtime


def test_sqlite_db_path_for_runtime_prefers_override():
    path = sqlite_db_path_for_runtime(override=" /tmp/x.db ", in_container=False, package_dir=Path("/x"))
    assert path == "/tmp/x.db"


def test_sqlite_db_path_for_runtime_defaults_to_container_path():
    path = sqlite_db_path_for_runtime(override=None, in_container=True, package_dir=Path("/x"))
    assert path == "/app/data/database.db"


def test_sqlite_db_path_for_runtime_defaults_to_package_data_dir():
    path = sqlite_db_path_for_runtime(override=None, in_container=False, package_dir=Path("/pkg"))
    assert path == "/pkg/data/database.db"


def test_load_db_config_from_env_defaults_to_sqlite():
    cfg = load_db_config_from_env({}, sqlite_path="/tmp/test.db")
    assert cfg.backend == "sqlite"
    assert cfg.database_url == "sqlite:////tmp/test.db"


def test_load_db_config_from_env_prefers_postgres_when_dsn_present():
    cfg = load_db_config_from_env({"DATABASE_URL": "postgresql://x"}, sqlite_path="/tmp/test.db")
    assert cfg.backend == "postgres"
    assert cfg.database_url == "postgresql://x"


def test_load_db_config_from_env_raises_when_postgres_requested_without_dsn():
    with pytest.raises(RuntimeError):
        load_db_config_from_env({"DB_BACKEND": "postgres"}, sqlite_path="/tmp/test.db")

