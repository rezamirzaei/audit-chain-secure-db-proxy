from __future__ import annotations

from types import SimpleNamespace

from database_server.security.credentials import (
    DEFAULT_TOTP_TIME_STEP_SECONDS,
    PasswordService,
    TotpService,
    get_totp_token,
    verify_totp,
)


def test_totp_token_is_deterministic_and_verifiable_with_fixed_time():
    secret = "JBSWY3DPEHPK3PXP"
    now = 1_700_000_000.0

    token = get_totp_token(secret, now=now)
    assert token == get_totp_token(secret, now=now)
    assert verify_totp(secret, token, now=now, window=0) is True

    # With a strict window, the token should not validate a full step later.
    assert verify_totp(secret, token, now=now + DEFAULT_TOTP_TIME_STEP_SECONDS, window=0) is False
    # With a 1-step tolerance, it should validate.
    assert verify_totp(secret, token, now=now + DEFAULT_TOTP_TIME_STEP_SECONDS, window=1) is True


def test_totp_service_allows_clock_injection():
    secret = "JBSWY3DPEHPK3PXP"
    now = 1_700_000_000.0
    service = TotpService(now_fn=lambda: now)

    token = service.get_token(secret)
    assert service.verify(secret, token, window=0) is True


def test_password_service_upgrades_plaintext_values():
    password_service = PasswordService()

    ok, needs_upgrade = password_service.verify_value("pw", "pw")
    assert ok is True
    assert needs_upgrade is True

    dummy_session = SimpleNamespace(added=[], committed=False)
    dummy_session.add = lambda obj: dummy_session.added.append(obj)
    dummy_session.commit = lambda: setattr(dummy_session, "committed", True)

    dummy_user = SimpleNamespace(password="pw")
    assert password_service.verify_and_upgrade(dummy_session, dummy_user, "password", "pw") is True
    assert isinstance(dummy_user.password, str)
    assert dummy_user.password.startswith("$argon2")
    assert dummy_session.committed is True
