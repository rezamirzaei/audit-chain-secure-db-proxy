from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .upstream_client import JsonDict

LOGIN_REQUEST_TIMEOUT_SECONDS = 10
SESSION_CHECK_TIMEOUT_SECONDS = 5
PROXY_REQUEST_TIMEOUT_SECONDS = 30
UPSTREAM_LOGIN_PATH = "/api/login"
UPSTREAM_SESSION_PATH = "/api/session"


@dataclass(frozen=True)
class CredentialVaultConfig:
    """Configuration knobs for upstream interaction and timeouts."""

    login_timeout_seconds: int = LOGIN_REQUEST_TIMEOUT_SECONDS
    session_check_timeout_seconds: int = SESSION_CHECK_TIMEOUT_SECONDS
    proxy_request_timeout_seconds: int = PROXY_REQUEST_TIMEOUT_SECONDS
    upstream_login_path: str = UPSTREAM_LOGIN_PATH
    upstream_session_path: str = UPSTREAM_SESSION_PATH


@dataclass
class CredentialVaultState:
    """Mutable state for a single user's captured credentials and auth progress."""

    credentials: JsonDict = field(default_factory=dict)
    totp_info: JsonDict = field(default_factory=dict)
    security_info: JsonDict = field(default_factory=dict)
    session_cookies: JsonDict = field(default_factory=dict)
    auth_state: JsonDict = field(default_factory=dict)
    active_session: bool | None = None
    last_login: datetime | None = None

