import base64
import hashlib
import hmac
import secrets
import struct
import time

from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from werkzeug.security import check_password_hash

# ==================== TOTP (Time-based One-Time Password) Implementation ====================


def decode_totp_secret(secret: str) -> bytes:
    normalized = secret.upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    return base64.b32decode(normalized + padding)


def totp_code_for_counter(secret: str, counter: int) -> str:
    key = decode_totp_secret(secret)
    counter_bytes = struct.pack(">Q", counter)
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack(">I", hmac_hash[offset : offset + 4])[0]
    code = (code & 0x7FFFFFFF) % 1000000
    return str(code).zfill(6)


def generate_totp_secret() -> str:
    """Generate a random TOTP secret"""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8")


def get_totp_token(secret: str, time_step: int = 30) -> str:
    """Generate current TOTP token"""
    counter = int(time.time() // time_step)
    return totp_code_for_counter(secret, counter)


def verify_totp(secret: str, token: str, window: int = 1) -> bool:
    """Verify TOTP token with time window tolerance"""
    for i in range(-window, window + 1):
        counter = int(time.time() // 30) + i
        expected = totp_code_for_counter(secret, counter)
        if hmac.compare_digest(token, expected):
            return True
    return False


def get_totp_uri(secret: str, username: str, issuer: str = "DataVault") -> str:
    """Generate otpauth URI for QR code"""
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"


# ==================== Password hashing / upgrade helpers ====================


_password_hasher = PasswordHasher()


def is_hash(value: str) -> bool:
    if not value:
        return False
    return value.startswith(("pbkdf2:", "scrypt:", "argon2:", "$argon2"))


def is_argon2(value: str) -> bool:
    return bool(value) and value.startswith("$argon2")


def hash_value(value: str) -> str:
    return _password_hasher.hash(value)


def verify_value(stored: str, provided: str) -> tuple[bool, bool]:
    if stored is None or provided is None:
        return False, False

    if is_argon2(stored):
        try:
            ok = _password_hasher.verify(stored, provided)
            return ok, _password_hasher.check_needs_rehash(stored) if ok else False
        except argon2_exceptions.VerifyMismatchError:
            return False, False
        except Exception:
            return False, False

    if is_hash(stored):
        ok = check_password_hash(stored, provided)
        return ok, ok

    compare_ok = bool(hmac.compare_digest(stored, provided))
    return compare_ok, compare_ok


class PasswordService:
    """Encapsulates password hashing and upgrade rules."""

    @staticmethod
    def is_hash(value: str) -> bool:
        return is_hash(value)

    @staticmethod
    def hash_value(value: str) -> str:
        return hash_value(value)

    @staticmethod
    def verify_value(stored: str, provided: str) -> tuple[bool, bool]:
        return verify_value(stored, provided)

    def verify_and_upgrade(self, session, user, field: str, provided: str) -> bool:
        stored = getattr(user, field)
        ok, needs_upgrade = verify_value(stored, provided)
        if ok and needs_upgrade:
            setattr(user, field, hash_value(provided))
            session.add(user)
            session.commit()
        return ok


class TotpService:
    """Encapsulates TOTP operations."""

    @staticmethod
    def generate_secret() -> str:
        return generate_totp_secret()

    @staticmethod
    def get_token(secret: str, time_step: int = 30) -> str:
        return get_totp_token(secret, time_step=time_step)

    @staticmethod
    def verify(secret: str, token: str, window: int = 1) -> bool:
        return verify_totp(secret, token, window=window)
