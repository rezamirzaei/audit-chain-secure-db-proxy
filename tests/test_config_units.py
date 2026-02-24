from __future__ import annotations

from database_server.config import AppConfig
from proxy_clone.config import ProxyCloneConfig


def test_database_server_config_defaults_secure_cookie_when_certs_exist(monkeypatch):
    monkeypatch.setenv("APP_ENV", "demo")
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)

    monkeypatch.setattr("database_server.config.SSLConfig.has_certificates", lambda: True)
    config = AppConfig.from_env()
    assert config.session_cookie_secure is True


def test_database_server_config_uses_safe_int_parsing(monkeypatch):
    monkeypatch.setenv("APP_ENV", "demo")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "bogus")
    monkeypatch.setenv("RATE_LIMIT_MAX_ATTEMPTS", "bogus")

    config = AppConfig.from_env()
    assert config.rate_limit_window_seconds == 600
    assert config.rate_limit_max_attempts == 5


def test_proxy_clone_config_defaults_secure_cookie_when_certs_exist(monkeypatch):
    monkeypatch.setenv("APP_ENV", "demo")
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)

    monkeypatch.setattr("proxy_clone.config.SSLConfig.has_certificates", lambda: True)
    config = ProxyCloneConfig.from_env()
    assert config.session_cookie_secure is True

