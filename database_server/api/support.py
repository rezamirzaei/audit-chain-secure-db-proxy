from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from .schemas import ApiErrorResponse, AuthenticatedUser, LoginStepResponse, LoginSuccessResponse

JsonBody = dict[str, Any]
JsonResponse = tuple[JsonBody, int]

LOGIN_BUCKET = "login"
INVALID_SESSION_STATE_MESSAGE = "Invalid session state. Start from login."
AUTH_USERS_TABLE = "auth_users"


class PasswordServiceLike(Protocol):
    def verify_and_upgrade(self, session: Any, user: Any, field: str, provided: str) -> bool: ...


class TotpServiceLike(Protocol):
    def verify(self, secret: str, token: str, window: int = 1) -> bool: ...


class AuthUserLike(Protocol):
    id: int
    username: str
    role: str
    totp_enabled: bool | None
    totp_secret: str | None
    security_question: str | None


@dataclass
class ApiResponseFactory:
    session_store: MutableMapping[str, Any]

    @staticmethod
    def model(model: Any) -> JsonBody:
        return model.model_dump(mode="json")

    def error(self, error: str, status: int, message: str | None = None) -> JsonResponse:
        return self.model(ApiErrorResponse(error=error, message=message)), status

    def invalid_session_state(self) -> JsonResponse:
        return self.error(INVALID_SESSION_STATE_MESSAGE, 400)

    def current_authenticated_user(self) -> AuthenticatedUser:
        return AuthenticatedUser(
            id=int(self.session_store["user_id"]),
            username=str(self.session_store["username"]),
            role=str(self.session_store["role"]),
        )

    def login_success(self) -> JsonResponse:
        return (
            self.model(
                LoginSuccessResponse(
                    success=True,
                    authenticated=True,
                    user=self.current_authenticated_user(),
                )
            ),
            200,
        )

    def login_step(
        self,
        *,
        next_step: Literal["totp", "security"],
        message: str,
        requires_2fa: bool | None = None,
        security_question: str | None = None,
    ) -> JsonResponse:
        return (
            self.model(
                LoginStepResponse(
                    success=True,
                    next_step=next_step,
                    message=message,
                    requires_2fa=requires_2fa,
                    security_question=security_question,
                )
            ),
            200,
        )


@dataclass
class LoginSessionState:
    session_store: MutableMapping[str, Any]

    def pending_user_id(self) -> int | None:
        raw_user_id = self.session_store.get("pending_user_id")
        if raw_user_id is None:
            return None
        try:
            return int(raw_user_id)
        except (TypeError, ValueError):
            return None

    def set_password_verified(self, user: AuthUserLike) -> None:
        self.session_store["pending_user_id"] = user.id
        self.session_store["pending_username"] = user.username
        self.session_store["pending_role"] = user.role
        self.session_store["pending_totp_enabled"] = user.totp_enabled
        self.session_store["auth_step"] = "password_verified"

    def mark_totp_verified(self) -> None:
        self.session_store["auth_step"] = "totp_verified"

    def has_expected_step(self, expected_step: str) -> bool:
        return "pending_user_id" in self.session_store and self.session_store.get("auth_step") == expected_step

    def expected_security_step(self) -> str:
        return "totp_verified" if self.session_store.get("pending_totp_enabled") else "password_verified"
