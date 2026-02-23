import base64
import hashlib
import hmac
import secrets
import struct
import time

from argon2 import PasswordHasher, exceptions as argon2_exceptions
from werkzeug.security import check_password_hash


# ==================== TOTP (Time-based One-Time Password) Implementation ====================


def generate_totp_secret() -> str:
    """Generate a random TOTP secret"""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8")


def get_totp_token(secret: str, time_step: int = 30) -> str:
    """Generate current TOTP token"""
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    counter = int(time.time() // time_step)
    counter_bytes = struct.pack(">Q", counter)
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack(">I", hmac_hash[offset : offset + 4])[0]
    code = (code & 0x7FFFFFFF) % 1000000
    return str(code).zfill(6)


def verify_totp(secret: str, token: str, window: int = 1) -> bool:
    """Verify TOTP token with time window tolerance"""
    for i in range(-window, window + 1):
        counter = int(time.time() // 30) + i
        key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
        counter_bytes = struct.pack(">Q", counter)
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        code = struct.unpack(">I", hmac_hash[offset : offset + 4])[0]
        code = (code & 0x7FFFFFFF) % 1000000
        expected = str(code).zfill(6)
        if token == expected:
            return True
    return False


def get_totp_uri(secret: str, username: str, issuer: str = "DataVault") -> str:
    """Generate otpauth URI for QR code"""
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"


# ==================== Password hashing / upgrade helpers ====================


_password_hasher = PasswordHasher()


def _is_hash(value: str) -> bool:
    if not value:
        return False
    return value.startswith(("pbkdf2:", "scrypt:", "argon2:", "$argon2"))


def _is_argon2(value: str) -> bool:
    return bool(value) and value.startswith("$argon2")


def _hash_value(value: str) -> str:
    return _password_hasher.hash(value)


def _verify_value(stored: str, provided: str) -> tuple[bool, bool]:
    if stored is None or provided is None:
        return False, False

    if _is_argon2(stored):
        try:
            ok = _password_hasher.verify(stored, provided)
            return ok, _password_hasher.check_needs_rehash(stored) if ok else False
        except argon2_exceptions.VerifyMismatchError:
            return False, False
        except Exception:
            return False, False

    if _is_hash(stored):
        ok = check_password_hash(stored, provided)
        return ok, ok

    compare_ok = bool(hmac.compare_digest(stored, provided))
    return compare_ok, compare_ok


def _verify_and_upgrade(db, user_id: int, field: str, stored: str, provided: str) -> bool:
    ok, needs_upgrade = _verify_value(stored, provided)
    if ok and needs_upgrade:
        db.execute(f"UPDATE auth_users SET {field} = ? WHERE id = ?", (_hash_value(provided), user_id))
        db.commit()
    return ok
