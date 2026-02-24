from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import ProxyCloneConfig
from shared.session_config import configure_sessions


class ProxyCloneBootstrap:
    def __init__(self, config: ProxyCloneConfig) -> None:
        self._config = config

    def create_app(self) -> Flask:
        app = Flask(__name__)
        app.secret_key = self._config.secret_key
        app.config["SESSION_COOKIE_HTTPONLY"] = self._config.session_cookie_http_only
        app.config["SESSION_COOKIE_SECURE"] = self._config.session_cookie_secure
        app.config["SESSION_COOKIE_SAMESITE"] = self._config.session_cookie_samesite
        self.apply_proxy(app)
        self.configure_sessions(app)
        return app

    def apply_proxy(self, app: Flask) -> None:
        if self._config.trust_proxy:
            app.wsgi_app = ProxyFix(cast(Any, app.wsgi_app), x_for=1, x_proto=1, x_host=1, x_port=1)

    def configure_sessions(self, app: Flask) -> None:
        session_dir = Path(__file__).resolve().parent / "data" / "sessions"
        configure_sessions(
            app,
            redis_url=self._config.redis_url,
            session_key_prefix=self._config.session_key_prefix,
            session_dir=session_dir,
        )
