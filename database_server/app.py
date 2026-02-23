"""
Container 1: Database Server
A real database application with MVC architecture, SQLite database,
and multi-factor authentication (password + TOTP 2FA)
"""

import os
from datetime import datetime
from typing import Any, cast

from flask import Flask, g, request, session

from .api_blueprint import DatabaseApiBlueprintDependencies, create_api_blueprint
from .api_schemas import (
    HealthResponse,
    LoginApiRequest,
    LogoutResponse,
    QueryApiRequest,
    SessionResponse,
    TablePaginationParams,
    TablePathParams,
    TotpCurrentResponse,
)
from .api_services import DatabaseApiService
from .api_validation import RequestPayloadValidationError, RequestValidator
from .common import (
    ContextInjector,
    SecurityHeadersManager,
    enforce_csrf,
    handle_request_validation_error,
    login_required,
)
from .db import init_db as init_database
from .runtime import DatabaseServerRuntime
from .services import AuditService, QueryService, SchemaService, TableService, UserService
from .ssl_utils import get_ssl_context
from .web_routes import DatabaseWebRoutes

runtime = DatabaseServerRuntime()
app = runtime.app
logger = runtime.logger
apply_security_headers = SecurityHeadersManager.set_security_headers(app)
PENDING_SESSION_KEYS = (
    "pending_totp_secret",
    "pending_totp_enabled",
    "pending_security_question",
    "pending_security_answer",
    "auth_step",
)


def client_ip() -> str:
    """Get client IP address, with support for proxied requests."""
    return request.remote_addr or "unknown"


def is_rate_limited(bucket: str) -> bool:
    """Check if client has exceeded rate limit for a bucket."""
    ip = client_ip()
    return runtime.rate_limiter.is_limited(bucket, ip)


def record_failed_attempt(bucket: str) -> None:
    """Record a failed attempt for rate limiting."""
    ip = client_ip()
    runtime.rate_limiter.record_failure(bucket, ip)


@app.context_processor
def inject_csrf_token() -> dict[str, Any]:
    """Inject CSRF token into template context."""
    return ContextInjector.inject_base_context()


@app.before_request
def before_request_handlers() -> None:
    """Register before-request handlers."""
    enforce_csrf()


@app.after_request
def after_request_handlers(response: Any) -> Any:
    """Register after-request handlers."""
    return apply_security_headers(response)


@app.errorhandler(RequestPayloadValidationError)
def handle_validation_error(error: RequestPayloadValidationError) -> tuple[dict[str, Any], int]:
    """Handle request validation errors."""
    return handle_request_validation_error(error)


def get_db() -> Any:
    """Get SQLAlchemy session for this request."""
    db_session = getattr(g, "_db_session", None)
    if db_session is None:
        db_session = g._db_session = runtime.db_manager.session()
    return db_session


def api_service() -> Any:
    db_session = get_db()
    return DatabaseApiService(
        session_store=cast(Any, session),
        db_session=db_session,
        user_service=UserService(db_session),
        audit_service=AuditService(db_session),
        schema_service=SchemaService(runtime.db_manager.engine),
        query_service=QueryService(db_session),
        table_service=TableService(db_session),
        password_service=runtime.password_service,
        totp_service=runtime.totp_service,
        complete_login=complete_login,
        is_rate_limited=is_rate_limited,
        record_failed_attempt=record_failed_attempt,
        enable_query_console=runtime.config.enable_query_console,
    )


def build_api_blueprint_dependencies() -> DatabaseApiBlueprintDependencies:
    return DatabaseApiBlueprintDependencies(
        request_validator=RequestValidator,
        login_request_model=LoginApiRequest,
        query_request_model=QueryApiRequest,
        table_path_model=TablePathParams,
        table_pagination_model=TablePaginationParams,
        health_response_model=HealthResponse,
        session_response_model=SessionResponse,
        totp_response_model=TotpCurrentResponse,
        logout_response_model=LogoutResponse,
        api_service_factory=api_service,
        enable_totp_test_endpoint=runtime.config.enable_totp_test_endpoint,
        get_db=get_db,
        get_totp_token=runtime.totp_service.get_token,
        login_required=login_required,
        log_action=log_action,
    )


@app.teardown_appcontext
def close_connection(_exception: BaseException | None) -> None:
    db_session = getattr(g, "_db_session", None)
    if db_session is not None:
        db_session.close()


def log_action(action: str, table_name: str | None = None, query: str | None = None) -> None:
    """Log user actions for audit."""
    if "user_id" in session:
        service = api_service()
        service.audit_service.log_action(
            user_id=session["user_id"],
            action=action,
            table_name=table_name,
            query=query,
        )


def complete_login() -> None:
    """Complete the login process after all auth steps."""
    session.permanent = True
    session["user_id"] = session.pop("pending_user_id")
    session["username"] = session.pop("pending_username")
    session["role"] = session.pop("pending_role")
    session["login_time"] = datetime.now().isoformat()

    # Clean up pending session data
    for key in PENDING_SESSION_KEYS:
        session.pop(key, None)

    log_action("login_complete")


web_routes = DatabaseWebRoutes(
    app=app,
    runtime=runtime,
    get_db=get_db,
    login_required=login_required,
    log_action=log_action,
    is_rate_limited=is_rate_limited,
    record_failed_attempt=record_failed_attempt,
    complete_login=complete_login,
)
web_routes.register()


app.register_blueprint(
    create_api_blueprint(build_api_blueprint_dependencies())
)


# Initialize database on startup
with app.app_context():
    init_database(
        runtime.db_manager,
        demo_mode=runtime.config.demo_mode,
        enable_totp_test_endpoint=runtime.config.enable_totp_test_endpoint,
        log_info=logger.info,
    )


def create_app() -> Flask:
    """Application factory entrypoint for WSGI servers and tests."""
    return app


if __name__ == "__main__":
    # Get SSL certificates if available
    ssl_cert, ssl_key = get_ssl_context()

    # Determine port (5000 in Docker, 5001 locally to avoid macOS AirPlay conflict)
    default_port = 5000 if os.path.exists("/app") else 5001
    port = int(os.environ.get("PORT", default_port))

    # Start server with or without HTTPS
    if ssl_cert and ssl_key:
        logger.info("Starting server with HTTPS on port %s (cert: %s)...", port, ssl_cert)
        app.run(host="0.0.0.0", port=port, debug=runtime.config.debug_mode, ssl_context=(ssl_cert, ssl_key))
    else:
        logger.info("SSL certificates not found. Starting server with HTTP on port %s...", port)
        app.run(host="0.0.0.0", port=port, debug=runtime.config.debug_mode)
