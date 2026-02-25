"""Gunicorn configuration for database_server."""

from __future__ import annotations

import os


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return default


bind = "0.0.0.0:5000"
workers = env_int("WEB_CONCURRENCY", 2)
threads = env_int("WEB_THREADS", 4)
timeout = env_int("WEB_TIMEOUT", 60)
accesslog = "-"
errorlog = "-"
