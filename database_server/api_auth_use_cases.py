from __future__ import annotations

from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import Any

from .api_schemas import LoginApiRequest
from .api_support import (
    LOGIN_BUCKET,
    ApiResponseFactory,
    AuthUserLike,
    JsonResponse,
    LoginSessionState,
    PasswordServiceLike,
    TotpServiceLike,
)
from .services import UserService


@dataclass
class AuthLoginUseCases:
    session_store: MutableMapping[str, Any]
    db_session: Any
    user_service: UserService
    password_service: PasswordServiceLike
    totp_service: TotpServiceLike
    complete_login: Callable[[], None]
    is_rate_limited: Callable[[str], bool]
    record_failed_attempt: Callable[[str], None]
    responses: ApiResponseFactory
    login_state: LoginSessionState

    def login(self, payload: LoginApiRequest) -> JsonResponse:
        if self.is_rate_limited(LOGIN_BUCKET):
            return self.responses.error("Too many login attempts. Please try again later.", 429)

        handlers: dict[str, Callable[[LoginApiRequest], JsonResponse]] = {
            "password": self.login_password,
            "totp": self.login_totp,
            "security": self.login_security,
        }
        handler = handlers.get(payload.step)
        if handler is None:
            return self.responses.error(f"Unknown step: {payload.step}", 400)
        return handler(payload)

    def login_password(self, payload: LoginApiRequest) -> JsonResponse:
        username = payload.username
        password = payload.password
        if username is None or password is None:
            return self.responses.error("Missing credentials", 400)

        user = self.user_service.get_by_username(username)
        if user is None or not self.password_service.verify_and_upgrade(self.db_session, user, "password", password):
            self.record_login_failure()
            return self.responses.error("Invalid credentials", 401)

        self.login_state.set_password_verified(user)

        if user.totp_enabled:
            return self.responses.login_step(
                next_step="totp",
                message="Password verified. Please provide 2FA code.",
                requires_2fa=True,
            )

        if user.security_question:
            return self.responses.login_step(
                next_step="security",
                security_question=user.security_question,
                message="Password verified. Please answer security question.",
            )

        return self.complete_login_and_success()

    def login_totp(self, payload: LoginApiRequest) -> JsonResponse:
        if not self.login_state.has_expected_step("password_verified"):
            return self.responses.invalid_session_state()

        totp_code = payload.totp_code or ""
        format_error = self.validate_totp_code(totp_code)
        if format_error is not None:
            return format_error

        user, error_response = self.require_pending_user()
        if error_response is not None:
            return error_response

        if not user.totp_secret or not self.totp_service.verify(user.totp_secret, totp_code):
            self.record_login_failure()
            return self.responses.error("Invalid 2FA code", 401)

        self.login_state.mark_totp_verified()
        return self.continue_to_security_or_complete(user, verified_message="2FA verified. Please answer security question.")

    def login_security(self, payload: LoginApiRequest) -> JsonResponse:
        if not self.login_state.has_expected_step(self.login_state.expected_security_step()):
            return self.responses.invalid_session_state()

        user, error_response = self.require_pending_user()
        if error_response is not None:
            return error_response

        answer = (payload.security_answer or "").lower()
        if not self.password_service.verify_and_upgrade(self.db_session, user, "security_answer", answer):
            self.record_login_failure()
            return self.responses.error("Incorrect security answer", 401)

        return self.complete_login_and_success()

    def complete_login_and_success(self) -> JsonResponse:
        self.complete_login()
        return self.responses.login_success()

    def continue_to_security_or_complete(self, user: AuthUserLike, *, verified_message: str) -> JsonResponse:
        if user.security_question:
            return self.responses.login_step(
                next_step="security",
                security_question=user.security_question,
                message=verified_message,
            )
        return self.complete_login_and_success()

    def require_pending_user(self) -> tuple[AuthUserLike | None, JsonResponse | None]:
        user_id = self.login_state.pending_user_id()
        if user_id is None:
            return None, self.responses.invalid_session_state()

        user = self.user_service.get_by_id(user_id)
        if user is None:
            return None, self.responses.invalid_session_state()
        return user, None

    def validate_totp_code(self, totp_code: str) -> JsonResponse | None:
        if not totp_code or not totp_code.isdigit() or len(totp_code) != 6:
            self.record_login_failure()
            return self.responses.error("Invalid 2FA code format. Code must be exactly 6 digits.", 400)
        return None

    def record_login_failure(self) -> None:
        self.record_failed_attempt(LOGIN_BUCKET)

