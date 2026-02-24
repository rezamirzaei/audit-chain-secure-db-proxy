"""Compatibility wrapper for `proxy_clone.web.auth_guards`."""

from __future__ import annotations

from .web.auth_guards import (
    WAITING_SECURITY_STEP as WAITING_SECURITY_STEP,
    WAITING_TOTP_STEP as WAITING_TOTP_STEP,
    ProxyAuthGuards as ProxyAuthGuards,
    pending_connect_step as pending_connect_step,
)

__all__ = [
    "WAITING_SECURITY_STEP",
    "WAITING_TOTP_STEP",
    "ProxyAuthGuards",
    "pending_connect_step",
]

