from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

import requests

from .auth_flow import (
    PASSWORD_STEP,
    WAITING_SECURITY_STEP,
    WAITING_TOTP_STEP,
    LoginAttempt,
    LoginOutcome,
    LoginReply,
    current_auth_step,
    determine_login_attempt,
    interpret_login_reply,
)
from .upstream_client import JsonDict, UpstreamClient
from .vault_types import CredentialVaultConfig, CredentialVaultState


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
        self._state.record_totp_code(totp_code, captured_at=self.current_time_iso())

    def store_security_answer(self, question: Any, answer: Any) -> None:
        self._state.record_security_answer(question, answer, captured_at=self.current_time_iso())

    def store_cookies(self, cookies: Any) -> None:
        try:
            cookies_dict = requests.utils.dict_from_cookiejar(cookies)
        except Exception:  # pragma: no cover - defensive conversion fallback
            cookies_dict = dict(cookies)
        self._state.record_session_cookies(cookies_dict, last_login=self.current_time())

    def login_request(self, payload: JsonDict) -> tuple[requests.Response, JsonDict]:
        return self.client.post_json(self.config.upstream_login_path, payload, timeout=self.config.login_timeout_seconds)

    def error_result(self, message: str, *, state: JsonDict | None = None) -> JsonDict:
        result: JsonDict = {"success": False, "error": message}
        if state is not None:
            result["state"] = state
        return result

    def mark_authenticated(self, data: JsonDict) -> JsonDict:
        self.store_cookies(self.client.session.cookies)
        self.active_session = True
        self.auth_state = {"authenticated": True, "user": data.get("user")}
        return {"success": True, "data": data}

    def require_security(self, question: Any, data: JsonDict) -> JsonDict:
        self.auth_state["current_step"] = WAITING_SECURITY_STEP
        self.auth_state["security_question"] = question
        return {
            "success": False,
            "error": "Security question verification required",
            "requires_security": True,
            "security_question": question,
            "message": "Please answer your security question",
            "state": data,
        }

    def require_totp(self, data: JsonDict) -> JsonDict:
        self.auth_state["current_step"] = WAITING_TOTP_STEP
        return {
            "success": False,
            "error": "Two-factor authentication required",
            "requires_totp": True,
            "message": "Please enter your 2FA code from your authenticator app",
            "state": data,
        }

    def reset_to_password_step(self) -> None:
        self.auth_state = {"current_step": PASSWORD_STEP}

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
        outcome = interpret_login_reply(
            LoginReply(status_code=response.status_code, data=data),
            failure_message=failure_message,
            incomplete_message=incomplete_message,
            include_state_on_incomplete=include_state_on_incomplete,
            reset_password_on_invalid_session=reset_password_on_invalid_session,
        )

        return self.apply_login_outcome(
            outcome,
            failure_message=failure_message,
            incomplete_message=incomplete_message,
        )

    def apply_login_outcome(
        self,
        outcome: LoginOutcome,
        *,
        failure_message: str,
        incomplete_message: str,
    ) -> JsonDict:
        if outcome.reset_to_password:
            self.reset_to_password_step()

        if outcome.kind == "error":
            return self.error_result(str(outcome.error or failure_message))
        if outcome.kind == "require_totp":
            return self.require_totp(outcome.state or {})
        if outcome.kind == "require_security":
            return self.require_security(outcome.security_question, outcome.state or {})
        if outcome.kind == "authenticated":
            return self.mark_authenticated(outcome.authenticated_data or {})
        return self.error_result(str(outcome.error or incomplete_message), state=outcome.state)

    def handle_totp_step(self, totp_code: str) -> JsonDict:
        self.debug("Sending TOTP code to server...")
        self.store_totp_code(totp_code)
        response, data = self.login_request({"step": "totp", "totp_code": totp_code})
        return self.finalize_login_step_result(
            response=response,
            data=data,
            failure_message="2FA verification failed",
            incomplete_message="Authentication failed after 2FA",
            reset_password_on_invalid_session=True,
        )

    def handle_security_step(self, security_answer: str) -> JsonDict:
        question = self.auth_state.get("security_question", "")
        self.store_security_answer(question, security_answer)
        response, data = self.login_request({"step": "security", "security_answer": security_answer})
        return self.finalize_login_step_result(
            response=response,
            data=data,
            failure_message="Security verification failed",
            incomplete_message="Authentication failed after security question",
        )

    def password_login_payload(self) -> JsonDict:
        return {
            "step": "password",
            "username": self.credentials["username"],
            "password": self.credentials["password"],
        }

    def handle_password_step(self) -> JsonDict:
        self.reset_to_password_step()
        response, data = self.login_request(self.password_login_payload())
        return self.finalize_login_step_result(
            response=response,
            data=data,
            failure_message="Password verification failed",
            incomplete_message="Authentication incomplete",
            include_state_on_incomplete=True,
        )

    def determine_login_attempt(self, *, totp_code: str | None, security_answer: str | None) -> LoginAttempt:
        step = current_auth_step(self.auth_state)
        self.debug("current_step = %s", step)
        return determine_login_attempt(self.auth_state, totp_code=totp_code, security_answer=security_answer)

    def run_login_attempt(self, attempt: LoginAttempt) -> JsonDict:
        if attempt.handler == "password":
            return self.handle_password_step()
        if attempt.handler == "totp":
            return self.handle_totp_step(attempt.value or "")
        return self.handle_security_step(attempt.value or "")

    def multi_step_login(self, totp_code: str | None = None, security_answer: str | None = None) -> JsonDict:
        self.debug(
            "multi_step_login called - totp_code=%s, security_answer=%s",
            bool(totp_code),
            bool(security_answer),
        )
        self.debug("current auth_state = %s", self.auth_state)

        if not self.credentials:
            return {"success": False, "error": "No credentials stored"}

        try:
            attempt = self.determine_login_attempt(totp_code=totp_code, security_answer=security_answer)
            return self.run_login_attempt(attempt)
        except Exception as exc:  # pragma: no cover - network/client failures
            return {"success": False, "error": str(exc)}

    def login(self, totp_code: str | None = None, security_answer: str | None = None) -> JsonDict:
        return self.multi_step_login(totp_code, security_answer)

    def upstream_session_authenticated(self) -> bool:
        response, data = self.client.get_json(
            self.config.upstream_session_path,
            timeout=self.config.session_check_timeout_seconds,
        )
        if response.status_code != 200:
            return False
        return bool(data.get("authenticated"))

    def reauthenticate(self) -> bool:
        result = self.login(security_answer=self.security_info.get("answer"))
        return bool(result.get("success", False))

    def ensure_session(self) -> bool:
        if not self.credentials:
            return False

        try:
            if self.upstream_session_authenticated():
                return True
        except Exception:
            pass

        return self.reauthenticate()

    def request_upstream(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        return self.client.request(method, path, timeout=self.config.proxy_request_timeout_seconds, **kwargs)

    def proxy_request(self, method: str, path: str, **kwargs: Any) -> Any | None:
        if not self.ensure_session():
            return None

        try:
            return self.request_upstream(method, path, **kwargs)
        except Exception:
            return None

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
