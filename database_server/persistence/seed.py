from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth_utils import PasswordService, TotpService
from ..domain import build_audit_payload, hash_audit_payload
from ..models import AuditLog, AuthUser, Base, Department, Employee, Project
from .session_manager import DatabaseSessionManager


def init_db(manager: DatabaseSessionManager, demo_mode: bool, enable_totp_test_endpoint: bool, log_info) -> None:
    Base.metadata.create_all(manager.engine)
    seeder = DatabaseSeeder(manager, demo_mode=demo_mode, enable_totp_test_endpoint=enable_totp_test_endpoint)
    seeder.seed(log_info=log_info)


class DatabaseSeeder:
    def __init__(self, manager: DatabaseSessionManager, demo_mode: bool, enable_totp_test_endpoint: bool):
        self.manager = manager
        self.demo_mode = demo_mode
        self.enable_totp_test_endpoint = enable_totp_test_endpoint
        self.password_service = PasswordService()
        self.totp_service = TotpService()

    def seed(self, log_info) -> None:
        with self.manager.session() as session:
            self.ensure_default_users(session, log_info=log_info)
            self.ensure_sample_data(session)
            self.backfill_audit_hashes(session)
            session.commit()

    def ensure_default_users(self, session: Session, log_info) -> None:
        if session.execute(select(func.count(AuthUser.id))).scalar_one() > 0:
            self.upgrade_unhashed_users(session, log_info=log_info)
            return

        admin_secret = self.totp_service.generate_secret()
        analyst_secret = self.totp_service.generate_secret()

        admin = AuthUser(
            username="admin",
            password=self.password_service.hash_value("SecurePass123!"),
            role="admin",
            totp_secret=admin_secret,
            totp_enabled=True,
            security_question="What is your favorite color?",
            security_answer=self.password_service.hash_value("blue"),
        )
        analyst = AuthUser(
            username="analyst",
            password=self.password_service.hash_value("AnalystPass456!"),
            role="analyst",
            totp_secret=analyst_secret,
            totp_enabled=True,
            security_question="What is your first pet's name?",
            security_answer=self.password_service.hash_value("fluffy"),
        )
        session.add_all([admin, analyst])

        if self.demo_mode and self.enable_totp_test_endpoint:
            log_info("2FA SETUP: Admin TOTP secret: %s", admin_secret)
            log_info("2FA SETUP: Admin TOTP token: %s", self.totp_service.get_token(admin_secret))
            log_info("2FA SETUP: Analyst TOTP secret: %s", analyst_secret)
            log_info("2FA SETUP: Analyst TOTP token: %s", self.totp_service.get_token(analyst_secret))

    def upgrade_unhashed_users(self, session: Session, log_info) -> None:
        users = session.execute(select(AuthUser)).scalars().all()
        any_updated = False
        for user in users:
            updated = False
            if user.password and not self.password_service.is_hash(user.password):
                user.password = self.password_service.hash_value(user.password)
                updated = True
            if user.security_answer and not self.password_service.is_hash(user.security_answer):
                user.security_answer = self.password_service.hash_value(user.security_answer.lower())
                updated = True
            if user.totp_enabled is None:
                user.totp_enabled = True
                updated = True
            if updated:
                session.add(user)
                any_updated = True
        if any_updated:
            log_info("Upgraded legacy auth hashes to Argon2")

    def ensure_sample_data(self, session: Session) -> None:
        if session.execute(select(func.count(Employee.id))).scalar_one() > 0:
            return

        employees = [
            Employee(
                name="Alice Johnson",
                email="alice@example.com",
                department="Engineering",
                salary=120000,
                hire_date=date(2020, 1, 15),
                is_active=True,
            ),
            Employee(
                name="Bob Smith",
                email="bob@example.com",
                department="Marketing",
                salary=85000,
                hire_date=date(2019, 3, 10),
                is_active=True,
            ),
            Employee(
                name="Charlie Brown",
                email="charlie@example.com",
                department="Sales",
                salary=95000,
                hire_date=date(2021, 7, 22),
                is_active=True,
            ),
        ]
        session.add_all(employees)
        session.flush()

        departments = [
            Department(name="Engineering", budget=500000, manager_id=employees[0].id),
            Department(name="Marketing", budget=250000, manager_id=employees[1].id),
            Department(name="Sales", budget=300000, manager_id=employees[2].id),
        ]
        session.add_all(departments)
        session.flush()

        projects = [
            Project(
                name="Project Apollo",
                description="New product development",
                department_id=departments[0].id,
                start_date=date(2024, 1, 1),
                status="active",
            ),
            Project(
                name="Project Mercury",
                description="Marketing campaign",
                department_id=departments[1].id,
                start_date=date(2024, 2, 15),
                status="active",
            ),
            Project(
                name="Project Gemini",
                description="Sales expansion",
                department_id=departments[2].id,
                start_date=date(2024, 3, 20),
                status="active",
            ),
        ]
        session.add_all(projects)

    def backfill_audit_hashes(self, session: Session) -> None:
        logs = session.execute(select(AuditLog).order_by(AuditLog.id)).scalars().all()
        if not logs or all(log.entry_hash for log in logs):
            return

        prev_hash = ""
        for log in logs:
            timestamp = log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else str(log.timestamp)
            payload = build_audit_payload(
                prev_hash,
                timestamp=timestamp,
                user_id=log.user_id,
                action=log.action,
                table_name=log.table_name,
                query=log.query,
            )
            entry_hash = hash_audit_payload(payload)
            log.prev_hash = prev_hash
            log.entry_hash = entry_hash
            session.add(log)
            prev_hash = entry_hash
