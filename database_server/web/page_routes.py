from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask, render_template, request, session
from sqlalchemy import func, select
from sqlalchemy.orm import aliased

from ..persistence.models import AuditLog, AuthUser, Department, Employee, Project


class DatabasePageRoutes:
    def __init__(
        self,
        *,
        app: Flask,
        runtime: Any,
        get_db: Callable[[], Any],
        login_required: Callable[[Any], Any],
    ) -> None:
        self.app = app
        self.runtime = runtime
        self.get_db = get_db
        self.login_required = login_required

    def register(self) -> None:
        self.app.add_url_rule("/dashboard", view_func=self.login_required(self.dashboard))
        self.app.add_url_rule("/employees", view_func=self.login_required(self.employees))
        self.app.add_url_rule("/departments", view_func=self.login_required(self.departments))
        self.app.add_url_rule("/projects", view_func=self.login_required(self.projects))
        self.app.add_url_rule("/query", view_func=self.login_required(self.query_page))
        self.app.add_url_rule("/audit", view_func=self.login_required(self.audit_log_page))

    @staticmethod
    def redirect_dashboard():
        from flask import redirect, url_for

        return redirect(url_for("dashboard"))

    @staticmethod
    def dashboard_stats_payload(db_session: Any) -> dict[str, Any]:
        return {
            "employees": db_session.execute(select(func.count(Employee.id))).scalar_one(),
            "departments": db_session.execute(select(func.count(Department.id))).scalar_one(),
            "projects": db_session.execute(select(func.count(Project.id)).where(Project.status == "active")).scalar_one(),
            "total_salary": db_session.execute(
                select(func.sum(Employee.salary)).where(Employee.is_active.is_(True))
            ).scalar_one()
            or 0,
        }

    @staticmethod
    def recent_employees(db_session: Any, limit: int = 5) -> list[Employee]:
        return (
            db_session.execute(select(Employee).order_by(Employee.hire_date.desc()).limit(limit)).scalars().all()
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
