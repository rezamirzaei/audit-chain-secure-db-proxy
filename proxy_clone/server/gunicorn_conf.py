"""Gunicorn configuration for proxy_clone."""

from __future__ import annotations

import os

from shared.ssl_utils import get_ssl_context


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return default


bind = f"0.0.0.0:{env_int('PORT', 8080)}"
workers = env_int("WEB_CONCURRENCY", 2)
threads = env_int("WEB_THREADS", 4)
worker_class = "gthread"
timeout = env_int("WEB_TIMEOUT", 60)
accesslog = "-"
errorlog = "-"

_ssl_cert, _ssl_key = get_ssl_context()
if _ssl_cert and _ssl_key:
    certfile = _ssl_cert
    keyfile = _ssl_key
