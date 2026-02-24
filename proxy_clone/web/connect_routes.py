from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, cast

from flask import jsonify, redirect, render_template, request, session, url_for

from .types import ProxyVaultLike

CONNECT_STEP_CREDENTIALS = "credentials"
CONNECT_STEP_TOTP = "totp"
CONNECT_STEP_SECURITY = "security"
VALID_CONNECT_STEPS = {CONNECT_STEP_CREDENTIALS, CONNECT_STEP_TOTP, CONNECT_STEP_SECURITY}
ConnectStep = Literal["credentials", "totp", "security"]


def connect_step_request_value() -> str:
    if request.method == "GET":
        return str(request.args.get("step", CONNECT_STEP_CREDENTIALS))
    return str(request.form.get("step", CONNECT_STEP_CREDENTIALS))


def normalize_connect_step(step: str) -> ConnectStep:
    if step in VALID_CONNECT_STEPS:
        return cast(ConnectStep, step)
    return CONNECT_STEP_CREDENTIALS


def totp_validation_error(totp_code: str) -> str | None:
    if not totp_code:
        return "Please enter the 2FA code"
    if not totp_code.isdigit() or len(totp_code) != 6:
        return "2FA code must be exactly 6 digits"
    return None


class ProxyConnectController:
    """Connect/disconnect flows for capturing credentials and completing upstream auth."""

    def __init__(
        self,
        *,
        vault: ProxyVaultLike,
        drop_current_vault: Callable[[], None],
        debug: Callable[..., None],
        proxy_features_enabled: bool,
    ) -> None:
        self.vault = vault
        self.drop_current_vault = drop_current_vault
        self.debug = debug
        self.proxy_features_enabled = proxy_features_enabled

    def home(self):
        """Proxy home page: minimal query interface for end users."""
        if not self.proxy_features_enabled:
            return jsonify({"error": "Proxy demo features are disabled in production"}), 404
        status = self.vault.get_status()
        return render_template("home.html", status=status)

    def connect(self):
        """Page to capture/enter credentials and perform multi-step auth."""
        step = self.read_connect_step()
        self.log_connect_state(step)

        redirect_response = self.guard_connect_step(step)
        if redirect_response is not None:
            return redirect_response

        error = None
        if request.method == "POST":
            error, redirect_response = self.handle_connect_post(step)
            if redirect_response is not None:
                return redirect_response

        return self.render_connect(step=step, error=error)

    def read_connect_step(self) -> ConnectStep:
        return normalize_connect_step(connect_step_request_value())

    def log_connect_state(self, step: str) -> None:
        self.debug("connect() called - method=%s, step=%s", request.method, step)
        self.debug("vault.auth_state = %s", self.vault.auth_state)
        self.debug("vault.credentials = %s", bool(self.vault.credentials))

    def guard_connect_step(self, step: ConnectStep):
        if step in {CONNECT_STEP_TOTP, CONNECT_STEP_SECURITY} and not self.vault.credentials:
            return self.redirect_connect_step(CONNECT_STEP_CREDENTIALS)
        return None

    def handle_connect_post(self, step: ConnectStep) -> tuple[str | None, Any | None]:
        handlers: dict[ConnectStep, Callable[[], tuple[str | None, Any | None]]] = {
            CONNECT_STEP_CREDENTIALS: self.handle_credentials_submit,
            CONNECT_STEP_TOTP: self.handle_totp_submit,
            CONNECT_STEP_SECURITY: self.handle_security_submit,
        }
        return handlers[step]()

    def handle_credentials_submit(self) -> tuple[str | None, Any | None]:
        username = request.form.get("username")
        password = request.form.get("password")
        self.vault.store_credentials(username, password)
        self.vault.auth_state = {}

        result = self.vault.login()
        self.debug("credentials login result: %s", result)
        return self.resolve_connect_result(
            result,
            default_error="Failed to connect",
            allow_totp_redirect=True,
            allow_security_redirect=True,
            log_totp_redirect=True,
        )

    def handle_totp_submit(self) -> tuple[str | None, Any | None]:
        totp_code = request.form.get("totp_code", "").strip()
        self.debug("totp step - totp_code=%s, auth_state=%s", totp_code, self.vault.auth_state)

        validation_error = totp_validation_error(totp_code)
        if validation_error is not None:
            return validation_error, None

        result = self.vault.login(totp_code=totp_code)
        self.debug("totp login result: %s", result)
        return self.resolve_connect_result(
            result,
            default_error="Invalid 2FA code",
            allow_totp_redirect=False,
            allow_security_redirect=True,
        )

    def handle_security_submit(self) -> tuple[str | None, Any | None]:
        security_answer = request.form.get("security_answer", "").strip()
        if not security_answer:
            return "Please enter your security answer", None

        result = self.vault.login(security_answer=security_answer)
        self.debug("security login result: %s", result)
        return self.resolve_connect_result(
            result,
            default_error="Invalid security answer",
            allow_totp_redirect=False,
            allow_security_redirect=False,
        )

    def resolve_connect_result(
        self,
        result: dict[str, Any],
        *,
        default_error: str,
        allow_totp_redirect: bool,
        allow_security_redirect: bool,
        log_totp_redirect: bool = False,
    ) -> tuple[str | None, Any | None]:
        if result.get("success"):
            return None, redirect(url_for("home"))

        if allow_totp_redirect and result.get("requires_totp"):
            if log_totp_redirect:
                self.debug("Redirecting to totp step, auth_state = %s", self.vault.auth_state)
            return None, self.redirect_connect_step("totp")

        if allow_security_redirect and result.get("requires_security"):
            session["security_question"] = result.get("security_question")
            return None, self.redirect_connect_step("security")

        return str(result.get("error", default_error)), None

    def redirect_connect_step(self, step: ConnectStep):
        return redirect(url_for("connect", step=step))

    def render_connect(self, *, step: str, error: str | None):
        security_question = session.get("security_question") or self.vault.auth_state.get("security_question")
        return render_template(
            "connect.html",
            error=error,
            status=self.vault.get_status(),
            step=step,
            security_question=security_question,
        )

    def disconnect(self):
        """Clear stored credentials and all captured auth info."""
        self.vault.reset_auth(clear_credentials=True)
        self.drop_current_vault()
        session.pop("security_question", None)
        return redirect(url_for("connect"))

