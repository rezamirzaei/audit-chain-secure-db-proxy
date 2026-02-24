from __future__ import annotations

from collections.abc import Callable, MutableMapping
from typing import Any, cast

from flask import Flask, redirect, render_template, request, session, url_for
from pydantic import ValidationError

from ..api.auth_use_cases import AuthLoginUseCases
from ..api.schemas import LoginApiRequest
from ..api.support import LOGIN_BUCKET, ApiResponseFactory, LoginSessionState
from ..domain import UserService


class DatabaseAuthRoutes:
    def __init__(
        self,
        *,
        app: Flask,
        runtime: Any,
        get_db: Callable[[], Any],
        log_action: Callable[..., None],
        is_rate_limited: Callable[[str], bool],
        record_failed_attempt: Callable[[str], None],
        complete_login: Callable[[], None],
        debug_log: Callable[..., None] | None = None,
    ) -> None:
        self.app = app
        self.runtime = runtime
        self.get_db = get_db
        self.log_action = log_action
        self.is_rate_limited = is_rate_limited
        self.record_failed_attempt = record_failed_attempt
        self.complete_login = complete_login
        self.debug_log = debug_log

    def register(self) -> None:
        self.app.add_url_rule("/", view_func=self.index)
        self.app.add_url_rule("/login", view_func=self.login, methods=["GET", "POST"])
        self.app.add_url_rule("/verify-2fa", view_func=self.verify_2fa, methods=["GET", "POST"])
        self.app.add_url_rule("/verify-security", view_func=self.verify_security, methods=["GET", "POST"])
        self.app.add_url_rule("/logout", view_func=self.logout)

    def auth_use_cases(self) -> AuthLoginUseCases:
        db_session = self.get_db()
        session_store = cast(MutableMapping[str, Any], session)
        responses = ApiResponseFactory(session_store=session_store)
        login_state = LoginSessionState(session_store=session_store)
        return AuthLoginUseCases(
            session_store=session_store,
            db_session=db_session,
            user_service=self.get_user_service(db_session),
            password_service=self.runtime.password_service,
            totp_service=self.runtime.totp_service,
            complete_login=self.complete_login,
            is_rate_limited=self.is_rate_limited,
            record_failed_attempt=self.record_failed_attempt,
            responses=responses,
            login_state=login_state,
        )

    @staticmethod
    def redirect_login():
        return redirect(url_for("login"))

    @staticmethod
    def redirect_dashboard():
        return redirect(url_for("dashboard"))

    def render_login_page(self, *, error: str | None = None):
        return render_template("login.html", error=error)

    def render_verify_2fa_page(self, *, error: str | None = None):
        return render_template("verify_2fa.html", error=error, username=session.get("pending_username"))

    def render_verify_security_page(self, *, question: str, error: str | None = None):
        return render_template(
            "verify_security.html",
            error=error,
            question=question,
            username=session.get("pending_username"),
        )

    def get_user_service(self, db_session: Any) -> UserService:
        return UserService(db_session)

    def pending_security_question(self) -> str | None:
        question = session.get("pending_security_question")
        if isinstance(question, str) and question.strip():
            return question
        if "pending_security_question" in session:
            return None

        raw_user_id = session.get("pending_user_id")
        try:
            user_id = int(raw_user_id)
        except (TypeError, ValueError):
            return None

        db_session = self.get_db()
        user = self.get_user_service(db_session).get_by_id(user_id)
        if user is None:
            return None

        session["pending_security_question"] = user.security_question
        return user.security_question

    def complete_login_and_redirect_dashboard(self):
        self.complete_login()
        return self.redirect_dashboard()

    def index(self):
        if "user_id" in session:
            return self.redirect_dashboard()
        return self.redirect_login()

    def login(self):
        error = None

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            try:
                payload = LoginApiRequest(step="password", username=username, password=password)
            except ValidationError:
                self.record_failed_attempt(LOGIN_BUCKET)
                error = "Invalid username or password"
            else:
                body, status = self.auth_use_cases().login(payload)
                if status == 200 and body.get("authenticated"):
                    return self.redirect_dashboard()
                next_step = body.get("next_step")
                if status == 200 and next_step == "totp":
                    return redirect(url_for("verify_2fa"))
                if status == 200 and next_step == "security":
                    if "security_question" in body:
                        session["pending_security_question"] = body.get("security_question")
                    return redirect(url_for("verify_security"))
                error = str(body.get("error", "Invalid username or password"))

        return self.render_login_page(error=error)

    def verify_2fa(self):
        login_state = LoginSessionState(session_store=cast(MutableMapping[str, Any], session))
        if not login_state.has_expected_step("password_verified"):
            return self.redirect_login()

        error = None
        if request.method == "POST":
            totp_code = request.form.get("totp_code", "").strip()
            try:
                payload = LoginApiRequest(step="totp", totp_code=totp_code)
            except ValidationError:
                self.record_failed_attempt(LOGIN_BUCKET)
                error = "Authentication code must be exactly 6 digits."
            else:
                body, status = self.auth_use_cases().login(payload)
                if status == 200 and body.get("authenticated"):
                    return self.redirect_dashboard()
                if status == 200 and body.get("next_step") == "security":
                    if "security_question" in body:
                        session["pending_security_question"] = body.get("security_question")
                    return redirect(url_for("verify_security"))
                error = str(body.get("error", "Invalid authentication code. Please try again."))

        return self.render_verify_2fa_page(error=error)

    def verify_security(self):
        login_state = LoginSessionState(session_store=cast(MutableMapping[str, Any], session))
        expected_step = login_state.expected_security_step()
        if not login_state.has_expected_step(expected_step):
            return self.redirect_login()

        error = None
        question = self.pending_security_question()
        if not question:
            return self.complete_login_and_redirect_dashboard()

        if request.method == "POST":
            answer = request.form.get("security_answer", "").strip()
            try:
                payload = LoginApiRequest(step="security", security_answer=answer)
            except ValidationError:
                self.record_failed_attempt(LOGIN_BUCKET)
                error = "Please enter your security answer"
            else:
                body, status = self.auth_use_cases().login(payload)
                if status == 200 and body.get("authenticated"):
                    return self.redirect_dashboard()
                error = str(body.get("error", "Incorrect security answer. Please try again."))

        return self.render_verify_security_page(question=question, error=error)

    def logout(self):
        self.log_action("logout")
        session.clear()
        return self.redirect_login()
