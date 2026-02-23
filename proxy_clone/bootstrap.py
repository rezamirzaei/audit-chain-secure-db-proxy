from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from cachelib.file import FileSystemCache
from flask import Flask
from flask_session import Session
import redis as redis_lib
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import ProxyCloneConfig


class ProxyCloneBootstrap:
    def __init__(self, config: ProxyCloneConfig) -> None:
        self._config = config

    def create_app(self) -> Flask:
        app = Flask(__name__)
        app.secret_key = self._config.secret_key
        app.config["SESSION_COOKIE_HTTPONLY"] = self._config.session_cookie_http_only
        app.config["SESSION_COOKIE_SECURE"] = self._config.session_cookie_secure
        app.config["SESSION_COOKIE_SAMESITE"] = self._config.session_cookie_samesite
        self._apply_proxy(app)
        self._configure_sessions(app)
        return app

    def _apply_proxy(self, app: Flask) -> None:
        if self._config.trust_proxy:
            setattr(
                app,
                "wsgi_app",
                ProxyFix(cast(Any, app.wsgi_app), x_for=1, x_proto=1, x_host=1, x_port=1),
            )

    def _configure_sessions(self, app: Flask) -> None:
        if self._config.redis_url:
            app.config["SESSION_TYPE"] = "redis"
            app.config["SESSION_REDIS"] = redis_lib.from_url(self._config.redis_url)
            app.config["SESSION_KEY_PREFIX"] = self._config.session_key_prefix
        else:
            session_dir = Path(__file__).resolve().parent / "data" / "sessions"
            session_dir.mkdir(parents=True, exist_ok=True)
            app.config["SESSION_TYPE"] = "cachelib"
            app.config["SESSION_CACHELIB"] = FileSystemCache(cache_dir=str(session_dir))
        Session(app)
