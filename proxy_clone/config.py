from __future__ import annotations

import os
import secrets

from pydantic import BaseModel, ConfigDict

from shared.env_utils import parse_bool

from .ssl_utils import SSLConfig


class ProxyCloneConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    app_env: str
    demo_mode: bool
    debug_mode: bool
    trust_proxy: bool
    proxy_features_enabled: bool

    database_server_url: str
    ssl_verify: bool

    secret_key: str
    session_cookie_http_only: bool = True
    session_cookie_secure: bool
    session_cookie_samesite: str = "Lax"

    log_level: str = "INFO"
    redis_url: str | None = None
    session_key_prefix: str = "proxy_session:"

    @classmethod
    def from_env(cls) -> ProxyCloneConfig:
        app_env = os.environ.get("APP_ENV", "production").lower()
        demo_mode = app_env != "production"
        debug_mode = parse_bool(os.environ.get("FLASK_DEBUG"), False)
        trust_proxy = parse_bool(os.environ.get("TRUST_PROXY"), app_env == "production")
        proxy_features_enabled = parse_bool(os.environ.get("PROXY_FEATURES_ENABLED"), demo_mode)
        database_server_url = os.environ.get("DATABASE_SERVER_URL", "https://localhost:5001")
        ssl_verify = parse_bool(os.environ.get("SSL_VERIFY"), not demo_mode)
        secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
        session_cookie_secure = parse_bool(
            os.environ.get("SESSION_COOKIE_SECURE"),
            app_env == "production" or SSLConfig.has_certificates(),
        )
        session_cookie_samesite = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
        log_level = os.environ.get("LOG_LEVEL", "INFO")
        redis_url = os.environ.get("REDIS_URL")
        session_key_prefix = os.environ.get("SESSION_KEY_PREFIX", "proxy_session:")

        return cls(
            app_env=app_env,
            demo_mode=demo_mode,
            debug_mode=debug_mode,
            trust_proxy=trust_proxy,
            proxy_features_enabled=proxy_features_enabled,
            database_server_url=database_server_url,
            ssl_verify=ssl_verify,
            secret_key=secret_key,
            session_cookie_secure=session_cookie_secure,
            session_cookie_samesite=session_cookie_samesite,
            log_level=log_level,
            redis_url=redis_url,
            session_key_prefix=session_key_prefix,
        )
