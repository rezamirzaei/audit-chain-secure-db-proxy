"""Compatibility wrapper for `database_server.persistence.seed`."""

from __future__ import annotations

from .persistence.seed import DatabaseSeeder as DatabaseSeeder
from .persistence.seed import init_db as init_db

__all__ = ["DatabaseSeeder", "init_db"]

