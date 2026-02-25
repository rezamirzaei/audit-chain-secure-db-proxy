"""Authentication and MFA helpers (password hashing, TOTP)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from collections.abc import Callable
from typing import Any

from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from werkzeug.security import check_password_hash

DEFAULT_TOTP_TIME_STEP_SECONDS = 30
TOTP_TOKEN_LENGTH = 6


def normalize_totp_secret(secret: str) -> str:
    return secret.upper()


def decode_totp_secret(secret: str) -> bytes:
    normalized = normalize_totp_secret(secret)
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    return base64.b32decode(normalized + padding)


def totp_code_for_counter(secret: str, counter: int) -> str:
    key = decode_totp_secret(secret)
    counter_bytes = struct.pack(">Q", counter)
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack(">I", hmac_hash[offset : offset + 4])[0]
    code = (code & 0x7FFFFFFF) % 1000000
    return str(code).zfill(TOTP_TOKEN_LENGTH)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8")


def totp_counter(*, now: float, time_step: int) -> int:
    return int(now // time_step)


def get_totp_token(secret: str, *, now: float | None = None, time_step: int = DEFAULT_TOTP_TIME_STEP_SECONDS) -> str:
    now_value = time.time() if now is None else now
    return totp_code_for_counter(secret, totp_counter(now=now_value, time_step=time_step))


def verify_totp(
    secret: str,
    token: str,
    *,
    now: float | None = None,
    time_step: int = DEFAULT_TOTP_TIME_STEP_SECONDS,
    window: int = 1,
) -> bool:
    now_value = time.time() if now is None else now
    base_counter = totp_counter(now=now_value, time_step=time_step)
    for offset in range(-window, window + 1):
        expected = totp_code_for_counter(secret, base_counter + offset)
        if hmac.compare_digest(token, expected):
            return True
    return False


def totp_uri(secret: str, username: str, *, issuer: str = "DataVault") -> str:
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"


class TotpService:
    """Encapsulates TOTP operations with an injectable clock."""

    def __init__(
        self,
        *,
        time_step: int = DEFAULT_TOTP_TIME_STEP_SECONDS,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self._time_step = time_step
        self._now_fn = now_fn or time.time

    @staticmethod
    def generate_secret() -> str:
        return generate_totp_secret()

    def get_token(self, secret: str) -> str:
        return get_totp_token(secret, now=self._now_fn(), time_step=self._time_step)

    def verify(self, secret: str, token: str, window: int = 1) -> bool:
        return verify_totp(
            secret,
            token,
            now=self._now_fn(),
            time_step=self._time_step,
            window=window,
        )

    @staticmethod
    def uri(secret: str, username: str, *, issuer: str = "DataVault") -> str:
        return totp_uri(secret, username, issuer=issuer)


def is_hash(value: str) -> bool:
    if not value:
        return False
    return value.startswith(("pbkdf2:", "scrypt:", "argon2:", "$argon2"))


def is_argon2(value: str) -> bool:
    return bool(value) and value.startswith("$argon2")


class PasswordService:
    """Encapsulates password hashing and upgrade rules."""

    def __init__(self, hasher: PasswordHasher | None = None) -> None:
        self._hasher = hasher or PasswordHasher()

    @staticmethod
    def is_hash(value: str) -> bool:
        return is_hash(value)

    def hash_value(self, value: str) -> str:
        return self._hasher.hash(value)

    def verify_value(self, stored: str | None, provided: str | None) -> tuple[bool, bool]:
        if not stored or provided is None:
            return False, False

        if is_argon2(stored):
            try:
                # argon2's `verify()` returns `True` or raises. Using the exception
                # flow keeps mypy happy (some stubs type it as `Literal[True]`).
                self._hasher.verify(stored, provided)
            except argon2_exceptions.VerifyMismatchError:
                return False, False
            except Exception:
                return False, False
            return True, self._hasher.check_needs_rehash(stored)

        if is_hash(stored):
            ok = check_password_hash(stored, provided)
            return ok, ok  # upgrade to argon2 when verified

        ok = hmac.compare_digest(stored, provided)
        return bool(ok), bool(ok)  # upgrade to argon2 when verified

    def verify_and_upgrade(self, session: Any, user: Any, field: str, provided: str) -> bool:
        stored = getattr(user, field)
        ok, needs_upgrade = self.verify_value(stored, provided)
        if ok and needs_upgrade:
            setattr(user, field, self.hash_value(provided))
            session.add(user)
            session.commit()
        return ok
