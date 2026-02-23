from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

import requests

LOGIN_REQUEST_TIMEOUT_SECONDS = 10
SESSION_CHECK_TIMEOUT_SECONDS = 5
PROXY_REQUEST_TIMEOUT_SECONDS = 30
UPSTREAM_LOGIN_PATH = "/api/login"
UPSTREAM_SESSION_PATH = "/api/session"
PASSWORD_STEP = "password"
WAITING_TOTP_STEP = "waiting_totp"
WAITING_SECURITY_STEP = "waiting_security"
INVALID_SESSION_STATE_FRAGMENT = "Invalid session state"

JsonDict = dict[str, Any]
LoginHandlerName = Literal["password", "totp", "security"]


@dataclass(frozen=True)
class LoginAttempt:
    handler: LoginHandlerName
    value: str | None = None


class CredentialVault:
    """
    Stores captured credentials, auth factors, and upstream session cookies.
    Handles the multi-step authentication flow to the database server.
    """

    def __init__(
        self,
        *,
        database_server_url: str,
        ssl_verify: bool,
        debug_log: Callable[..., None] | None = None,
        now_fn: Callable[[], datetime] | None = None,
        session_factory: Callable[[], requests.Session] | None = None,
    ) -> None:
        self.database_server_url = database_server_url
        self.ssl_verify = ssl_verify
        self.debug_log = debug_log
        self.now_fn = now_fn or datetime.now
        self.session_factory = session_factory or requests.Session

        self.credentials: dict[str, Any] = {}
        self.totp_info: dict[str, Any] = {}
        self.security_info: dict[str, Any] = {}
        self.session_cookies: dict[str, Any] = {}
        self.active_session: bool | None = None
        self.last_login: datetime | None = None
        self.auto_refresh_running = False
        self.auth_state: dict[str, Any] = {}
        self.new_session()

    def debug(self, msg: str, *args: Any) -> None:
        if self.debug_log is not None:
            self.debug_log(msg, *args)

    def current_time(self) -> datetime:
        return self.now_fn()

    def current_time_iso(self) -> str:
        return self.current_time().isoformat()

    def upstream_url(self, path: str) -> str:
        return f"{self.database_server_url}{path}"

    def http_request(self, method: str, url: str, *, timeout: int, **kwargs: Any) -> requests.Response:
        return self.http_session.request(method, url, timeout=timeout, **kwargs)

    @staticmethod
    def response_json(response: requests.Response) -> JsonDict:
        try:
            payload = response.json()
        except ValueError:
            return {"error": "Upstream returned an invalid JSON response"}
        if isinstance(payload, dict):
            return payload
        return {"error": "Upstream returned an unexpected response payload"}

    def new_session(self) -> None:
        self.http_session = self.session_factory()
        self.http_session.verify = self.ssl_verify

    def reset_auth(self, clear_credentials: bool = False) -> None:
        if clear_credentials:
            self.credentials = {}
        self.totp_info = {}
        self.security_info = {}
        self.session_cookies = {}
        self.active_session = None
        self.auth_state = {}
        self.last_login = None
        self.new_session()

    def store_credentials(self, username: Any, password: Any) -> None:
        self.reset_auth(clear_credentials=False)
        self.credentials = {
            "username": username,
            "password": password,
            "captured_at": self.current_time_iso(),
        }

    def store_totp_code(self, totp_code: Any) -> None:
        self.totp_info = {
            "last_code": totp_code,
            "captured_at": self.current_time_iso(),
        }

    def store_security_answer(self, question: Any, answer: Any) -> None:
        self.security_info = {
            "question": question,
            "answer": answer,
            "captured_at": self.current_time_iso(),
        }

    def store_cookies(self, cookies: Any) -> None:
        self.session_cookies = dict(cookies)
        self.last_login = self.current_time()

    def get_session(self) -> requests.Session:
        return self.http_session

    def login_request(self, payload: JsonDict) -> tuple[requests.Response, JsonDict]:
        response = self.http_request(
            "POST",
            self.upstream_url(UPSTREAM_LOGIN_PATH),
            json=payload,
            timeout=LOGIN_REQUEST_TIMEOUT_SECONDS,
        )
        return response, self.response_json(response)

    def error_result(self, message: str, *, state: JsonDict | None = None) -> JsonDict:
        result: JsonDict = {"success": False, "error": message}
        if state is not None:
            result["state"] = state
        return result

    def mark_authenticated(self, data: JsonDict) -> JsonDict:
        self.store_cookies(self.http_session.cookies)
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

    def current_auth_step(self) -> str:
        return str(self.auth_state.get("current_step", PASSWORD_STEP))

    def reset_to_password_step(self) -> None:
        self.auth_state = {"current_step": PASSWORD_STEP}

    def login_error_message(self, data: JsonDict, fallback: str) -> str:
        return str(data.get("error", fallback))

    @staticmethod
    def upstream_next_step(data: JsonDict) -> str | None:
        next_step = data.get("next_step")
        if isinstance(next_step, str):
            return next_step
        return None

    @staticmethod
    def has_invalid_session_state_error(data: JsonDict) -> bool:
        error = data.get("error")
        return isinstance(error, str) and INVALID_SESSION_STATE_FRAGMENT in error

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
        if response.status_code != 200:
            if reset_password_on_invalid_session and self.has_invalid_session_state_error(data):
                self.reset_to_password_step()
            return self.error_result(self.login_error_message(data, failure_message))

        next_step = self.upstream_next_step(data)
        if next_step == "totp":
            return self.require_totp(data)
        if next_step == "security":
            return self.require_security(data.get("security_question"), data)
        if data.get("authenticated"):
            return self.mark_authenticated(data)

        if include_state_on_incomplete:
            return self.error_result(incomplete_message, state=data)
        return self.error_result(incomplete_message)

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
        current_step = self.current_auth_step()
        self.debug("current_step = %s", current_step)

        if totp_code and current_step != WAITING_SECURITY_STEP:
            return LoginAttempt(handler="totp", value=totp_code)
        if security_answer and current_step == WAITING_SECURITY_STEP:
            return LoginAttempt(handler="security", value=security_answer)
        return LoginAttempt(handler="password")

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
        response = self.http_request(
            "GET",
            self.upstream_url(UPSTREAM_SESSION_PATH),
            timeout=SESSION_CHECK_TIMEOUT_SECONDS,
        )
        if response.status_code != 200:
            return False
        data = self.response_json(response)
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
        return self.http_request(
            method,
            self.upstream_url(path),
            timeout=PROXY_REQUEST_TIMEOUT_SECONDS,
            **kwargs,
        )

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
