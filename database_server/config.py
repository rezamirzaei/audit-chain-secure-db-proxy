from __future__ import annotations

import os
import secrets
from pathlib import Path

from pydantic import BaseModel, ConfigDict


def parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def ssl_cert_available() -> bool:
    base_dir = Path(__file__).resolve().parent
    cert_key_pairs = [
        (Path("/app/certs/cert.pem"), Path("/app/certs/key.pem")),
        (base_dir / "certs" / "cert.pem", base_dir / "certs" / "key.pem"),
    ]
    return any(cert.exists() and key.exists() for cert, key in cert_key_pairs)


class AppConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    app_env: str
    demo_mode: bool
    debug_mode: bool
    trust_proxy: bool
    enable_totp_test_endpoint: bool
    enable_query_console: bool

    secret_key: str
    permanent_session_hours: int = 2
    session_cookie_name: str = "db_session"
    session_cookie_http_only: bool = True
    session_cookie_secure: bool
    session_cookie_samesite: str = "Lax"
    preferred_url_scheme: str | None = None

    log_level: str = "INFO"

    redis_url: str | None = None
    session_key_prefix: str = "db_session:"

    rate_limit_window_seconds: int = 600
    rate_limit_max_attempts: int = 5

    @classmethod
    def from_env(cls) -> AppConfig:
        app_env = os.environ.get("APP_ENV", "production").lower()
        demo_mode = app_env != "production"
        debug_mode = parse_bool(os.environ.get("FLASK_DEBUG"), False)
        trust_proxy = parse_bool(os.environ.get("TRUST_PROXY"), app_env == "production")
        enable_totp_test_endpoint = parse_bool(
            os.environ.get("ENABLE_TOTP_TEST_ENDPOINT"),
            demo_mode,
        )
        enable_query_console = parse_bool(
            os.environ.get("ENABLE_QUERY_CONSOLE"),
            demo_mode,
        )
        secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
        session_cookie_secure = parse_bool(
            os.environ.get("SESSION_COOKIE_SECURE"),
            app_env == "production" or ssl_cert_available(),
        )
        session_cookie_samesite = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
        preferred_url_scheme = "https" if app_env == "production" else None
        log_level = os.environ.get("LOG_LEVEL", "INFO")
        redis_url = os.environ.get("REDIS_URL")
        session_key_prefix = os.environ.get("SESSION_KEY_PREFIX", "db_session:")
        rate_limit_window_seconds = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "600"))
        rate_limit_max_attempts = int(os.environ.get("RATE_LIMIT_MAX_ATTEMPTS", "5"))

        return cls(
            app_env=app_env,
            demo_mode=demo_mode,
            debug_mode=debug_mode,
            trust_proxy=trust_proxy,
            enable_totp_test_endpoint=enable_totp_test_endpoint,
            enable_query_console=enable_query_console,
            secret_key=secret_key,
            session_cookie_secure=session_cookie_secure,
            session_cookie_samesite=session_cookie_samesite,
            preferred_url_scheme=preferred_url_scheme,
            log_level=log_level,
            redis_url=redis_url,
            session_key_prefix=session_key_prefix,
            rate_limit_window_seconds=rate_limit_window_seconds,
            rate_limit_max_attempts=rate_limit_max_attempts,
        )
