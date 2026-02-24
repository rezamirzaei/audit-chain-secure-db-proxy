from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from database_server.auth_utils import PasswordService
from database_server.models import AuthUser, Base
from database_server.persistence.seed import DatabaseSeeder


def test_database_seeder_upgrades_legacy_auth_hashes_and_defaults_totp_enabled():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)

    password_service = PasswordService()
    session = session_factory()
    session.add(
        AuthUser(
            username="legacy",
            password="plaintext",
            role="admin",
            totp_secret=None,
            totp_enabled=None,
            security_question="Q",
            security_answer="Blue",
        )
    )
    session.commit()

    logs: list[str] = []

    def log_info(msg: str, *args: object) -> None:
        logs.append(msg % args if args else msg)

    dummy_manager = SimpleNamespace()
    seeder = DatabaseSeeder(
        dummy_manager,
        demo_mode=False,
        enable_totp_test_endpoint=False,
        password_service=password_service,
    )
    seeder.upgrade_unhashed_users(session, log_info=log_info)

    upgraded = session.execute(select(AuthUser).where(AuthUser.username == "legacy")).scalar_one()
    assert upgraded.password.startswith("$argon2")
    assert password_service.verify_value(upgraded.password, "plaintext")[0] is True

    assert upgraded.security_answer.startswith("$argon2")
    # security_answer is normalized to lowercase before hashing.
    assert password_service.verify_value(upgraded.security_answer, "blue")[0] is True

    assert upgraded.totp_enabled is True
    assert logs == ["Upgraded legacy auth hashes to Argon2"]

