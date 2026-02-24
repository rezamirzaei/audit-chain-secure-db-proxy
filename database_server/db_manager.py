"""Compatibility wrapper for `database_server.persistence.session_manager`."""

from __future__ import annotations

from .persistence.session_manager import DatabaseSessionManager as DatabaseSessionManager

__all__ = ["DatabaseSessionManager"]

