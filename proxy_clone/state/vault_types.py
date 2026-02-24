from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

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

    def reset(self, *, clear_credentials: bool) -> None:
        if clear_credentials:
            self.credentials = {}
        self.totp_info = {}
        self.security_info = {}
        self.session_cookies = {}
        self.auth_state = {}
        self.active_session = None
        self.last_login = None

    def record_credentials(self, username: Any, password: Any, *, captured_at: str) -> None:
        self.credentials = {"username": username, "password": password, "captured_at": captured_at}

    def record_totp_code(self, totp_code: Any, *, captured_at: str) -> None:
        self.totp_info = {"last_code": totp_code, "captured_at": captured_at}

    def record_security_answer(self, question: Any, answer: Any, *, captured_at: str) -> None:
        self.security_info = {"question": question, "answer": answer, "captured_at": captured_at}

    def record_session_cookies(self, cookies: JsonDict, *, last_login: datetime) -> None:
        self.session_cookies = dict(cookies)
        self.last_login = last_login
