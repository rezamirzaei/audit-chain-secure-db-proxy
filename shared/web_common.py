"""Reusable Flask web helpers shared by service entrypoints."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast

from flask import Flask, abort, jsonify, request, session

F = TypeVar("F", bound=Callable[..., Any])


class CsrfTokenManager:
    """Manage CSRF token creation and validation against the Flask session."""

    @staticmethod
    def ensure_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    @staticmethod
    def validate_token(submitted: str | None) -> bool:
        token = session.get("csrf_token")
        if not token or not submitted:
            return False
        return hmac.compare_digest(token, submitted)

    @staticmethod
    def get_submitted_token() -> str | None:
        return request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")


class SecurityHeadersManager:
    """Attach common security headers to Flask responses."""

    @staticmethod
    def set_security_headers(app: Flask) -> Callable[[Any], Any]:
        def set_headers(response: Any) -> Any:
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
            if app.config.get("SESSION_COOKIE_SECURE"):
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            return response

        return set_headers


class ContextInjector:
    """Build shared template context."""

    @staticmethod
    def inject_base_context(**extra: Any) -> dict[str, Any]:
        context = {"csrf_token": CsrfTokenManager.ensure_token()}
        context.update(extra)
        return context


def enforce_csrf() -> None:
    """Flask before_request handler to enforce CSRF protection."""
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return

    # JSON API clients rely on session auth or explicit token auth and do not use form CSRF fields.
    if request.path.startswith("/api/") and request.is_json:
        return

    submitted = CsrfTokenManager.get_submitted_token()
    if not CsrfTokenManager.validate_token(submitted):
        abort(400, description="Invalid CSRF token")


def login_required(f: F) -> F:
    """Decorator to require authentication for view functions."""
    from flask import redirect, url_for

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if "user_id" not in session:
            if request.is_json:
                return jsonify({"error": "Unauthorized", "message": "Please login first"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return cast(F, decorated_function)


def create_feature_enabled_decorator(enabled: bool) -> Callable[[F], F]:
    """Decorator factory to return 404 when a feature is disabled."""

    def decorator(f: F) -> F:
        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            if not enabled:
                abort(404)
            return f(*args, **kwargs)

        return cast(F, decorated_function)

    return decorator


def handle_request_validation_error(error: Exception) -> tuple[dict[str, Any], int]:
    """Standard JSON error response for validation failures."""
    return (
        {
            "error": "Invalid request payload",
            "details": getattr(error, "errors", str(error)),
        },
        400,
    )

