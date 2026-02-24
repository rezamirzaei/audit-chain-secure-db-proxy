"""Compatibility facade for DB config/session/seeding APIs.

The repo historically imported everything from `database_server.db`. This module
keeps that import path stable while the internals live in focused modules.
"""

from __future__ import annotations

from .persistence.db_config import (
    DbConfig,
    load_db_config,
    load_db_config_from_env,
    sqlite_db_path,
    sqlite_db_path_for_runtime,
)
from .persistence.seed import DatabaseSeeder, init_db
from .persistence.session_manager import DatabaseSessionManager

__all__ = [
    "DbConfig",
    "DatabaseSeeder",
    "DatabaseSessionManager",
    "init_db",
    "load_db_config",
    "load_db_config_from_env",
    "sqlite_db_path",
    "sqlite_db_path_for_runtime",
]
