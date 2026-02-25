from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, cast

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import AppConfig
from shared.session_config import configure_sessions


class AppBootstrap:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def create_app(self) -> Flask:
        package_root = Path(__file__).resolve().parents[1]
        app = Flask(
            "database_server",
            template_folder=str(package_root / "templates"),
            static_folder=str(package_root / "static"),
        )
        self.apply_core_settings(app)
        self.apply_proxy(app)
        self.configure_sessions(app)
        return app

    def apply_core_settings(self, app: Flask) -> None:
        app.secret_key = self._config.secret_key
        app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=self._config.permanent_session_hours)
        app.config["SESSION_COOKIE_NAME"] = self._config.session_cookie_name
        app.config["SESSION_COOKIE_HTTPONLY"] = self._config.session_cookie_http_only
        app.config["SESSION_COOKIE_SECURE"] = self._config.session_cookie_secure
        app.config["SESSION_COOKIE_SAMESITE"] = self._config.session_cookie_samesite
        if self._config.preferred_url_scheme:
            app.config["PREFERRED_URL_SCHEME"] = self._config.preferred_url_scheme

    def apply_proxy(self, app: Flask) -> None:
        if self._config.trust_proxy:
            app.wsgi_app = ProxyFix(cast(Any, app.wsgi_app), x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    def configure_sessions(self, app: Flask) -> None:
        package_root = Path(__file__).resolve().parents[1]
        session_dir = package_root / "data" / "sessions"
        configure_sessions(
            app,
            redis_url=self._config.redis_url,
            session_key_prefix=self._config.session_key_prefix,
            session_dir=session_dir,
        )
