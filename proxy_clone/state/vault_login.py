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


class VaultLoginEngine:
    """Implements the upstream multi-step auth flow and updates vault state."""

    def __init__(
        self,
        *,
        client: UpstreamClient,
        config: CredentialVaultConfig,
        state: CredentialVaultState,
        debug: Callable[..., None],
        now_fn: Callable[[], datetime],
    ) -> None:
        self._client = client
        self._config = config
        self._state = state
        self._debug = debug
        self._now_fn = now_fn

    def captured_at_iso(self) -> str:
        return self._now_fn().isoformat()

    def login_request(self, payload: JsonDict) -> tuple[requests.Response, JsonDict]:
        return self._client.post_json(
            self._config.upstream_login_path,
            payload,
            timeout=self._config.login_timeout_seconds,
        )

    @staticmethod
    def error_result(message: str, *, state: JsonDict | None = None) -> JsonDict:
        result: JsonDict = {"success": False, "error": message}
        if state is not None:
            result["state"] = state
        return result

    def store_cookies(self, cookies: Any) -> None:
        try:
            cookies_dict = requests.utils.dict_from_cookiejar(cookies)
        except Exception:  # pragma: no cover - defensive conversion fallback
            cookies_dict = dict(cookies)
        self._state.record_session_cookies(cookies_dict, last_login=self._now_fn())

    def mark_authenticated(self, data: JsonDict) -> JsonDict:
        self.store_cookies(self._client.session.cookies)
        self._state.active_session = True
        self._state.auth_state = {"authenticated": True, "user": data.get("user")}
        return {"success": True, "data": data}

    def require_security(self, question: Any, data: JsonDict) -> JsonDict:
        self._state.auth_state["current_step"] = WAITING_SECURITY_STEP
        self._state.auth_state["security_question"] = question
        return {
            "success": False,
            "error": "Security question verification required",
            "requires_security": True,
            "security_question": question,
            "message": "Please answer your security question",
            "state": data,
        }

    def require_totp(self, data: JsonDict) -> JsonDict:
        self._state.auth_state["current_step"] = WAITING_TOTP_STEP
        return {
            "success": False,
            "error": "Two-factor authentication required",
            "requires_totp": True,
            "message": "Please enter your 2FA code from your authenticator app",
            "state": data,
        }

    def reset_to_password_step(self) -> None:
        self._state.auth_state = {"current_step": PASSWORD_STEP}

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

    def store_totp_code(self, totp_code: Any) -> None:
        self._state.record_totp_code(totp_code, captured_at=self.captured_at_iso())

    def store_security_answer(self, question: Any, answer: Any) -> None:
        self._state.record_security_answer(question, answer, captured_at=self.captured_at_iso())

    def handle_totp_step(self, totp_code: str) -> JsonDict:
        self._debug("Sending TOTP code to server...")
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
        question = self._state.auth_state.get("security_question", "")
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
            "username": self._state.credentials["username"],
            "password": self._state.credentials["password"],
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
        step = current_auth_step(self._state.auth_state)
        self._debug("current_step = %s", step)
        return determine_login_attempt(self._state.auth_state, totp_code=totp_code, security_answer=security_answer)

    def run_login_attempt(self, attempt: LoginAttempt) -> JsonDict:
        if attempt.handler == "password":
            return self.handle_password_step()
        if attempt.handler == "totp":
            return self.handle_totp_step(attempt.value or "")
        return self.handle_security_step(attempt.value or "")

    def multi_step_login(self, totp_code: str | None = None, security_answer: str | None = None) -> JsonDict:
        self._debug(
            "multi_step_login called - totp_code=%s, security_answer=%s",
            bool(totp_code),
            bool(security_answer),
        )
        self._debug("current auth_state = %s", self._state.auth_state)

        if not self._state.credentials:
            return {"success": False, "error": "No credentials stored"}

        try:
            attempt = self.determine_login_attempt(totp_code=totp_code, security_answer=security_answer)
            return self.run_login_attempt(attempt)
        except Exception as exc:  # pragma: no cover - network/client failures
            return {"success": False, "error": str(exc)}

