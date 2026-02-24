from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

import requests

from .upstream_client import JsonDict, UpstreamClient
from .vault_types import CredentialVaultConfig, CredentialVaultState
from .vault_login import VaultLoginEngine
from .vault_proxy import VaultProxyEngine


class CredentialVault:
    """Stores captured credentials + upstream cookies and performs multi-step auth."""

    # Keep this attribute for backwards compatibility with older tests/callers.
    response_json = staticmethod(UpstreamClient.response_json)

    def __init__(
        self,
        *,
        database_server_url: str,
        ssl_verify: bool,
        debug_log: Callable[..., None] | None = None,
        now_fn: Callable[[], datetime] | None = None,
        session_factory: Callable[[], requests.Session] | None = None,
        config: CredentialVaultConfig | None = None,
        client: UpstreamClient | None = None,
        state: CredentialVaultState | None = None,
    ) -> None:
        self.debug_log = debug_log
        self.now_fn = now_fn or datetime.now
        self.config = config or CredentialVaultConfig()

        self.client = client or UpstreamClient(
            base_url=database_server_url,
            ssl_verify=ssl_verify,
            session_factory=session_factory or requests.Session,
        )

        self._state = state or CredentialVaultState()
        self._login = VaultLoginEngine(
            client=self.client,
            config=self.config,
            state=self._state,
            debug=self.debug,
            now_fn=self.current_time,
        )
        self._proxy = VaultProxyEngine(
            client=self.client,
            config=self.config,
            state=self._state,
            login_fn=self._login.multi_step_login,
        )

    @property
    def state(self) -> CredentialVaultState:
        """Expose the mutable state container for higher-level orchestration and tests."""
        return self._state

    @property
    def credentials(self) -> JsonDict:
        return self._state.credentials

    @credentials.setter
    def credentials(self, value: JsonDict) -> None:
        self._state.credentials = value

    @property
    def totp_info(self) -> JsonDict:
        return self._state.totp_info

    @totp_info.setter
    def totp_info(self, value: JsonDict) -> None:
        self._state.totp_info = value

    @property
    def security_info(self) -> JsonDict:
        return self._state.security_info

    @security_info.setter
    def security_info(self, value: JsonDict) -> None:
        self._state.security_info = value

    @property
    def session_cookies(self) -> JsonDict:
        return self._state.session_cookies

    @session_cookies.setter
    def session_cookies(self, value: JsonDict) -> None:
        self._state.session_cookies = value

    @property
    def active_session(self) -> bool | None:
        return self._state.active_session

    @active_session.setter
    def active_session(self, value: bool | None) -> None:
        self._state.active_session = value

    @property
    def last_login(self) -> datetime | None:
        return self._state.last_login

    @last_login.setter
    def last_login(self, value: datetime | None) -> None:
        self._state.last_login = value

    @property
    def auth_state(self) -> JsonDict:
        return self._state.auth_state

    @auth_state.setter
    def auth_state(self, value: JsonDict) -> None:
        self._state.auth_state = value

    def debug(self, msg: str, *args: Any) -> None:
        if self.debug_log is not None:
            self.debug_log(msg, *args)

    def current_time(self) -> datetime:
        return self.now_fn()

    def current_time_iso(self) -> str:
        return self.current_time().isoformat()

    def new_session(self) -> None:
        self.client.new_session()

    def reset_auth(self, clear_credentials: bool = False) -> None:
        self._state.reset(clear_credentials=clear_credentials)
        self.new_session()

    def store_credentials(self, username: Any, password: Any) -> None:
        self.reset_auth(clear_credentials=False)
        self._state.record_credentials(username, password, captured_at=self.current_time_iso())

    def store_totp_code(self, totp_code: Any) -> None:
        self._login.store_totp_code(totp_code)

    def store_security_answer(self, question: Any, answer: Any) -> None:
        self._login.store_security_answer(question, answer)

    def store_cookies(self, cookies: Any) -> None:
        self._login.store_cookies(cookies)

    def login_request(self, payload: JsonDict) -> tuple[requests.Response, JsonDict]:
        return self._login.login_request(payload)

    def error_result(self, message: str, *, state: JsonDict | None = None) -> JsonDict:
        return self._login.error_result(message, state=state)

    def mark_authenticated(self, data: JsonDict) -> JsonDict:
        return self._login.mark_authenticated(data)

    def require_security(self, question: Any, data: JsonDict) -> JsonDict:
        return self._login.require_security(question, data)

    def require_totp(self, data: JsonDict) -> JsonDict:
        return self._login.require_totp(data)

    def reset_to_password_step(self) -> None:
        self._login.reset_to_password_step()

    def finalize_login_step_result(
        self,
        *,
        response: requests.Response,
        data: JsonDict,
        failure_message: str,
        incomplete_message: str,
        include_state_on_incomplete: bool = False,
        reset_password_on_invalid_session: bool = False,
    ) -> JsonDict:
        return self._login.finalize_login_step_result(
            response=response,
            data=data,
            failure_message=failure_message,
            incomplete_message=incomplete_message,
            include_state_on_incomplete=include_state_on_incomplete,
            reset_password_on_invalid_session=reset_password_on_invalid_session,
        )

    def apply_login_outcome(
        self,
        outcome: Any,
        *,
        failure_message: str,
        incomplete_message: str,
    ) -> JsonDict:
        return self._login.apply_login_outcome(
            outcome,
            failure_message=failure_message,
            incomplete_message=incomplete_message,
        )

    def handle_totp_step(self, totp_code: str) -> JsonDict:
        return self._login.handle_totp_step(totp_code)

    def handle_security_step(self, security_answer: str) -> JsonDict:
        return self._login.handle_security_step(security_answer)

    def password_login_payload(self) -> JsonDict:
        return self._login.password_login_payload()

    def handle_password_step(self) -> JsonDict:
        return self._login.handle_password_step()

    def determine_login_attempt(self, *, totp_code: str | None, security_answer: str | None) -> LoginAttempt:
        return self._login.determine_login_attempt(totp_code=totp_code, security_answer=security_answer)

    def run_login_attempt(self, attempt: LoginAttempt) -> JsonDict:
        return self._login.run_login_attempt(attempt)

    def multi_step_login(self, totp_code: str | None = None, security_answer: str | None = None) -> JsonDict:
        return self._login.multi_step_login(totp_code=totp_code, security_answer=security_answer)

    def login(self, totp_code: str | None = None, security_answer: str | None = None) -> JsonDict:
        return self.multi_step_login(totp_code, security_answer)

    def upstream_session_authenticated(self) -> bool:
        return self._proxy.upstream_session_authenticated()

    def reauthenticate(self) -> bool:
        return self._proxy.reauthenticate()

    def ensure_session(self) -> bool:
        return self._proxy.ensure_session()

    def request_upstream(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        return self._proxy.request_upstream(method, path, **kwargs)

    def proxy_request(self, method: str, path: str, **kwargs: Any) -> Any | None:
        return self._proxy.proxy_request(method, path, **kwargs)

    def get_status(self) -> dict[str, Any]:
        return {
            "has_credentials": bool(self.credentials),
            "username": self.credentials.get("username"),
            "captured_at": self.credentials.get("captured_at"),
            "has_totp": bool(self.totp_info),
            "has_security_answer": bool(self.security_info.get("answer")),
            "security_question": self.security_info.get("question"),
            "has_session": bool(self.session_cookies),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "active": self.active_session,
            "auth_state": self.auth_state,
        }

    def get_public_status(self) -> dict[str, Any]:
        return {
            "has_credentials": bool(self.credentials),
            "has_totp": bool(self.totp_info),
            "has_security_answer": bool(self.security_info.get("answer")),
            "has_session": bool(self.session_cookies),
            "active": bool(self.active_session),
        }
