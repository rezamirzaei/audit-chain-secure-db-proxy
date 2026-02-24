"""Shared Flask session configuration helpers (Redis or filesystem cache)."""

from __future__ import annotations

from pathlib import Path

import redis as redis_lib
from cachelib.file import FileSystemCache
from flask import Flask
from flask_session import Session


def configure_sessions(
    app: Flask,
    *,
    redis_url: str | None,
    session_key_prefix: str,
    session_dir: Path,
) -> None:
    if redis_url:
        app.config["SESSION_TYPE"] = "redis"
        app.config["SESSION_REDIS"] = redis_lib.from_url(redis_url)
        app.config["SESSION_KEY_PREFIX"] = session_key_prefix
    else:
        session_dir.mkdir(parents=True, exist_ok=True)
        app.config["SESSION_TYPE"] = "cachelib"
        app.config["SESSION_CACHELIB"] = FileSystemCache(cache_dir=str(session_dir))
    Session(app)

