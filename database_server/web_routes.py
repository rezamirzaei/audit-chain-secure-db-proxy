from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask, redirect, render_template, request, session, url_for
from sqlalchemy import func, select
from sqlalchemy.orm import aliased

from .models import AuditLog, AuthUser, Department, Employee, Project
from .services import UserService


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

    def index(self):
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    def login(self):
        error = None

        if request.method == "POST":
            if self.is_rate_limited("login"):
                error = "Too many login attempts. Please try again later."
                return render_template("login.html", error=error)

            username = request.form.get("username")
            password = request.form.get("password")

            db_session = self.get_db()
            user_service = UserService(db_session)
            user = user_service.get_by_username(username or "")

            if user and self.runtime.password_service.verify_and_upgrade(db_session, user, "password", password):
                session["pending_user_id"] = user.id
                session["pending_username"] = user.username
                session["pending_role"] = user.role
                session["pending_totp_enabled"] = user.totp_enabled
                session["auth_step"] = "password_verified"

                if user.totp_enabled:
                    return redirect(url_for("verify_2fa"))
                if user.security_question:
                    return redirect(url_for("verify_security"))

                self.complete_login()
                return redirect(url_for("dashboard"))

            self.record_failed_attempt("login")
            error = "Invalid username or password"

        return render_template("login.html", error=error)

    def verify_2fa(self):
        if "pending_user_id" not in session or session.get("auth_step") != "password_verified":
            return redirect(url_for("login"))

        error = None
        if request.method == "POST":
            if self.is_rate_limited("login"):
                error = "Too many attempts. Please try again later."
                return render_template("verify_2fa.html", error=error, username=session.get("pending_username"))

            db_session = self.get_db()
            user_service = UserService(db_session)
            pending_user_id = session.get("pending_user_id")
            user = user_service.get_by_id(int(pending_user_id))
            if not user:
                return redirect(url_for("login"))

            totp_code = request.form.get("totp_code", "").strip()
            if not totp_code or not totp_code.isdigit() or len(totp_code) != 6:
                error = "Authentication code must be exactly 6 digits."
            elif user.totp_secret and self.runtime.totp_service.verify(user.totp_secret, totp_code):
                session["auth_step"] = "totp_verified"
                if user.security_question:
                    return redirect(url_for("verify_security"))
                self.complete_login()
                return redirect(url_for("dashboard"))
            else:
                self.record_failed_attempt("login")
                error = "Invalid authentication code. Please try again."

        return render_template("verify_2fa.html", error=error, username=session.get("pending_username"))

    def verify_security(self):
        expected_step = "totp_verified" if session.get("pending_totp_enabled") else "password_verified"
        if "pending_user_id" not in session or session.get("auth_step") != expected_step:
            return redirect(url_for("login"))

        error = None
        db_session = self.get_db()
        user_service = UserService(db_session)
        pending_user_id = session.get("pending_user_id")
        user = user_service.get_by_id(int(pending_user_id))
        if not user:
            return redirect(url_for("login"))

        question = user.security_question
        if not question:
            self.complete_login()
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            if self.is_rate_limited("login"):
                error = "Too many attempts. Please try again later."
                return render_template(
                    "verify_security.html",
                    error=error,
                    question=question,
                    username=session.get("pending_username"),
                )

            answer = request.form.get("security_answer", "").strip()
            answer_norm = answer.lower()
            if self.runtime.password_service.verify_and_upgrade(db_session, user, "security_answer", answer_norm):
                self.complete_login()
                return redirect(url_for("dashboard"))

            self.record_failed_attempt("login")
            error = "Incorrect security answer. Please try again."

        return render_template(
            "verify_security.html",
            error=error,
            question=question,
            username=session.get("pending_username"),
        )

    def logout(self):
        self.log_action("logout")
        session.clear()
        return redirect(url_for("login"))

    def dashboard(self):
        db_session = self.get_db()
        stats = {
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
        recent_employees = db_session.execute(select(Employee).order_by(Employee.hire_date.desc()).limit(5)).scalars().all()
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
        departments_payload = [
            {
                "id": dept.id,
                "name": dept.name,
                "budget": dept.budget or 0,
                "employee_count": int(employee_count or 0),
            }
            for dept, employee_count in rows
        ]
        return render_template("departments.html", departments=departments_payload)

    def projects(self):
        db_session = self.get_db()
        dept_alias = aliased(Department)
        rows = db_session.execute(
            select(Project, dept_alias.name.label("department_name"))
            .outerjoin(dept_alias, Project.department_id == dept_alias.id)
            .order_by(Project.start_date.desc())
        ).all()
        projects_payload = [
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
        return render_template("projects.html", projects=projects_payload)

    def query_page(self):
        if not self.runtime.config.enable_query_console:
            return redirect(url_for("dashboard"))
        return render_template("query.html")

    def audit_log_page(self):
        if session.get("role") != "admin":
            return redirect(url_for("dashboard"))

        db_session = self.get_db()
        rows = db_session.execute(
            select(AuditLog, AuthUser.username)
            .outerjoin(AuthUser, AuditLog.user_id == AuthUser.id)
            .order_by(AuditLog.timestamp.desc())
            .limit(100)
        ).all()
        logs = [
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
        return render_template("audit.html", logs=logs)
