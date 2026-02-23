"""Compatibility wrapper around shared web helpers for database_server."""

from shared.web_common import (
    ContextInjector as ContextInjector,
    CsrfTokenManager as CsrfTokenManager,
    SecurityHeadersManager as SecurityHeadersManager,
    enforce_csrf as enforce_csrf,
    handle_request_validation_error as handle_request_validation_error,
    login_required as login_required,
)

__all__ = [
    "ContextInjector",
    "CsrfTokenManager",
    "SecurityHeadersManager",
    "enforce_csrf",
    "handle_request_validation_error",
    "login_required",
]
