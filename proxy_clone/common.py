"""Compatibility wrapper around shared web helpers for proxy_clone."""

from shared.web_common import (
    ContextInjector as ContextInjector,
    CsrfTokenManager as CsrfTokenManager,
    SecurityHeadersManager as SecurityHeadersManager,
    create_feature_enabled_decorator as create_feature_enabled_decorator,
    enforce_csrf as enforce_csrf,
    handle_request_validation_error as handle_request_validation_error,
)

__all__ = [
    "ContextInjector",
    "CsrfTokenManager",
    "SecurityHeadersManager",
    "create_feature_enabled_decorator",
    "enforce_csrf",
    "handle_request_validation_error",
]
