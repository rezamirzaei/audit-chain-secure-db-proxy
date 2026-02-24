from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

JsonDict = dict[str, Any]
LoginHandlerName = Literal["password", "totp", "security"]

PASSWORD_STEP = "password"
WAITING_TOTP_STEP = "waiting_totp"
WAITING_SECURITY_STEP = "waiting_security"
INVALID_SESSION_STATE_FRAGMENT = "Invalid session state"


@dataclass(frozen=True)
class LoginAttempt:
    handler: LoginHandlerName
    value: str | None = None


@dataclass(frozen=True)
class LoginReply:
    status_code: int
    data: JsonDict


@dataclass(frozen=True)
class LoginOutcome:
    kind: Literal["error", "require_totp", "require_security", "authenticated", "incomplete"]
    error: str | None = None
    security_question: Any | None = None
    state: JsonDict | None = None
    authenticated_data: JsonDict | None = None
    reset_to_password: bool = False


def current_auth_step(auth_state: Mapping[str, Any]) -> str:
    return str(auth_state.get("current_step", PASSWORD_STEP))


def determine_login_attempt(
    auth_state: Mapping[str, Any],
    *,
    totp_code: str | None,
    security_answer: str | None,
) -> LoginAttempt:
    step = current_auth_step(auth_state)
    if totp_code and step != WAITING_SECURITY_STEP:
        return LoginAttempt(handler="totp", value=totp_code)
    if security_answer and step == WAITING_SECURITY_STEP:
        return LoginAttempt(handler="security", value=security_answer)
    return LoginAttempt(handler="password")


def upstream_next_step(data: JsonDict) -> str | None:
    next_step = data.get("next_step")
    if isinstance(next_step, str):
        return next_step
    return None


def has_invalid_session_state_error(data: JsonDict) -> bool:
    error = data.get("error")
    return isinstance(error, str) and INVALID_SESSION_STATE_FRAGMENT in error


def login_error_message(data: JsonDict, fallback: str) -> str:
    return str(data.get("error", fallback))


def interpret_login_reply(
    reply: LoginReply,
    *,
    failure_message: str,
    incomplete_message: str,
    include_state_on_incomplete: bool = False,
    reset_password_on_invalid_session: bool = False,
) -> LoginOutcome:
    if reply.status_code != 200:
        return LoginOutcome(
            kind="error",
            error=login_error_message(reply.data, failure_message),
            reset_to_password=reset_password_on_invalid_session and has_invalid_session_state_error(reply.data),
        )

    next_step = upstream_next_step(reply.data)
    if next_step == "totp":
        return LoginOutcome(kind="require_totp", state=reply.data)
    if next_step == "security":
        return LoginOutcome(kind="require_security", security_question=reply.data.get("security_question"), state=reply.data)
    if reply.data.get("authenticated"):
        return LoginOutcome(kind="authenticated", authenticated_data=reply.data)

    if include_state_on_incomplete:
        return LoginOutcome(kind="incomplete", error=incomplete_message, state=reply.data)
    return LoginOutcome(kind="incomplete", error=incomplete_message)

