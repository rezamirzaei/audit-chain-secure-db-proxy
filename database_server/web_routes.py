from __future__ import annotations

from collections.abc import Callable, MutableMapping
from typing import Any, cast

from flask import Flask, redirect, render_template, request, session, url_for
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import aliased

from .api_auth_use_cases import AuthLoginUseCases
from .api_schemas import LoginApiRequest
from .api_support import ApiResponseFactory, LoginSessionState
from .models import AuditLog, AuthUser, Department, Employee, Project
from .services import UserService

LOGIN_BUCKET = "login"


class DatabaseWebRoutes:
    def __init__(
        self,
        *,
        app: Flask,
        runtime: Any,
        get_db: Callable[[], Any],
        login_required: Callable[[Any], Any],
        log_action: Callable[..., None],
        is_rate_limited: Callable[[str], bool],
        record_failed_attempt: Callable[[str], None],
        complete_login: Callable[[], None],
        debug_log: Callable[..., None] | None = None,
    ) -> None:
        self.app = app
        self.runtime = runtime
        self.get_db = get_db
        self.login_required = login_required
        self.log_action = log_action
        self.is_rate_limited = is_rate_limited
        self.record_failed_attempt = record_failed_attempt
        self.complete_login = complete_login
        self.debug_log = debug_log

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

    def register(self) -> None:
        self.app.add_url_rule("/", view_func=self.index)
        self.app.add_url_rule("/login", view_func=self.login, methods=["GET", "POST"])
        self.app.add_url_rule("/verify-2fa", view_func=self.verify_2fa, methods=["GET", "POST"])
        self.app.add_url_rule("/verify-security", view_func=self.verify_security, methods=["GET", "POST"])
        self.app.add_url_rule("/logout", view_func=self.logout)
        self.app.add_url_rule("/dashboard", view_func=self.login_required(self.dashboard))
        self.app.add_url_rule("/employees", view_func=self.login_required(self.employees))
        self.app.add_url_rule("/departments", view_func=self.login_required(self.departments))
        self.app.add_url_rule("/projects", view_func=self.login_required(self.projects))
        self.app.add_url_rule("/query", view_func=self.login_required(self.query_page))
        self.app.add_url_rule("/audit", view_func=self.login_required(self.audit_log_page))

    @staticmethod
    def redirect_login():
        return redirect(url_for("login"))

    @staticmethod
    def redirect_dashboard():
        return redirect(url_for("dashboard"))

    @staticmethod
    def pending_login_step_expected_for_security() -> str:
        return "totp_verified" if session.get("pending_totp_enabled") else "password_verified"

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

    @staticmethod
    def dashboard_stats_payload(db_session: Any) -> dict[str, Any]:
        return {
            "employees": db_session.execute(select(func.count(Employee.id))).scalar_one(),
            "departments": db_session.execute(select(func.count(Department.id))).scalar_one(),
            "projects": db_session.execute(
                select(func.count(Project.id)).where(Project.status == "active")
            ).scalar_one(),
            "total_salary": db_session.execute(
                select(func.sum(Employee.salary)).where(Employee.is_active.is_(True))
            ).scalar_one()
            or 0,
        }

    @staticmethod
    def recent_employees(db_session: Any, limit: int = 5) -> list[Employee]:
        return (
            db_session.execute(select(Employee).order_by(Employee.hire_date.desc()).limit(limit))
            .scalars()
            .all()
        )

    @staticmethod
    def departments_payload(rows: list[tuple[Department, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "id": dept.id,
                "name": dept.name,
                "budget": dept.budget or 0,
                "employee_count": int(employee_count or 0),
            }
            for dept, employee_count in rows
        ]

    @staticmethod
    def projects_payload(rows: list[tuple[Project, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "id": project.id,
                "name": project.name,
                "description": project.description or "",
                "department_name": department_name,
                "start_date": project.start_date,
                "end_date": project.end_date,
                "status": project.status,
            }
            for project, department_name in rows
        ]

    @staticmethod
    def audit_logs_payload(rows: list[tuple[AuditLog, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "id": log.id,
                "username": username,
                "action": log.action,
                "table_name": log.table_name,
                "query": log.query,
                "timestamp": log.timestamp,
            }
            for log, username in rows
        ]

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
        if "pending_user_id" not in session or session.get("auth_step") != "password_verified":
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
        expected_step = self.pending_login_step_expected_for_security()
        if "pending_user_id" not in session or session.get("auth_step") != expected_step:
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

    def dashboard(self):
        db_session = self.get_db()
        stats = self.dashboard_stats_payload(db_session)
        recent_employees = self.recent_employees(db_session)
        return render_template("dashboard.html", stats=stats, recent_employees=recent_employees)

    def employees(self):
        db_session = self.get_db()
        dept_filter = request.args.get("dept")
        stmt = select(Employee).order_by(Employee.name)
        if dept_filter:
            stmt = stmt.where(Employee.department == dept_filter)
        employees_list = db_session.execute(stmt).scalars().all()
        return render_template("employees.html", employees=employees_list)

    def departments(self):
        db_session = self.get_db()
        employee_alias = aliased(Employee)
        rows = db_session.execute(
            select(Department, func.count(employee_alias.id).label("employee_count"))
            .outerjoin(employee_alias, Department.name == employee_alias.department)
            .group_by(Department.id)
            .order_by(Department.name)
        ).all()
        departments_payload = self.departments_payload(rows)
        return render_template("departments.html", departments=departments_payload)

    def projects(self):
        db_session = self.get_db()
        dept_alias = aliased(Department)
        rows = db_session.execute(
            select(Project, dept_alias.name.label("department_name"))
            .outerjoin(dept_alias, Project.department_id == dept_alias.id)
            .order_by(Project.start_date.desc())
        ).all()
        projects_payload = self.projects_payload(rows)
        return render_template("projects.html", projects=projects_payload)

    def query_page(self):
        if not self.runtime.config.enable_query_console:
            return self.redirect_dashboard()
        return render_template("query.html")

    def audit_log_page(self):
        if session.get("role") != "admin":
            return self.redirect_dashboard()

        db_session = self.get_db()
        rows = db_session.execute(
            select(AuditLog, AuthUser.username)
            .outerjoin(AuthUser, AuditLog.user_id == AuthUser.id)
            .order_by(AuditLog.timestamp.desc())
            .limit(100)
        ).all()
        logs = self.audit_logs_payload(rows)
        return render_template("audit.html", logs=logs)
