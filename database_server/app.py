"""
Container 1: Database Server
A real database application with MVC architecture, SQLite database,
and multi-factor authentication (password + TOTP 2FA)
"""

from flask import Flask, request, jsonify, session, redirect, url_for, g, abort
from functools import wraps
from datetime import datetime
import os
import hmac
import secrets
from typing import Any, cast

from .db import init_db as init_database
from .api_schemas import (
    LoginApiRequest,
    QueryApiRequest,
    HealthResponse,
    SessionResponse,
    TotpCurrentResponse,
    LogoutResponse,
    TablePathParams,
    TablePaginationParams,
)
from .api_validation import RequestValidator, RequestPayloadValidationError
from .api_services import DatabaseApiService
from .api_blueprint import create_api_blueprint
from .services import AuditService, QueryService, SchemaService, TableService, UserService
from .runtime import DatabaseServerRuntime
from .web_routes import DatabaseWebRoutes

runtime = DatabaseServerRuntime()
app = runtime.app
logger = runtime.logger


def client_ip():
    # ProxyFix normalizes REMOTE_ADDR from trusted forwarded headers.
    return request.remote_addr or 'unknown'


def is_rate_limited(bucket):
    ip = client_ip()
    return runtime.rate_limiter.is_limited(bucket, ip)


def record_failed_attempt(bucket):
    ip = client_ip()
    runtime.rate_limiter.record_failure(bucket, ip)


def ensure_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': ensure_csrf_token()}


@app.before_request
def enforce_csrf():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        # JSON API clients are expected to use token-based auth; skip CSRF here
        if request.path.startswith('/api/') and request.is_json:
            return
        token = session.get('csrf_token')
        submitted = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not token or not submitted or not hmac.compare_digest(token, submitted):
            abort(400, description='Invalid CSRF token')


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    if app.config.get('SESSION_COOKIE_SECURE'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.errorhandler(RequestPayloadValidationError)
def handle_request_payload_validation_error(error):
    return jsonify({'error': 'Invalid request payload', 'details': error.errors}), 400

def get_db():
    """Get SQLAlchemy session for this request."""
    db_session = getattr(g, '_db_session', None)
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


@app.teardown_appcontext
def close_connection(exception):
    db_session = getattr(g, '_db_session', None)
    if db_session is not None:
        db_session.close()


def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Unauthorized', 'message': 'Please login first'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def log_action(action, table_name=None, query=None):
    """Log user actions for audit"""
    if 'user_id' in session:
        service = api_service()
        service.audit_service.log_action(
            user_id=session['user_id'],
            action=action,
            table_name=table_name,
            query=query,
        )


def complete_login():
    """Complete the login process after all auth steps"""
    session.permanent = True
    session['user_id'] = session.pop('pending_user_id')
    session['username'] = session.pop('pending_username')
    session['role'] = session.pop('pending_role')
    session['login_time'] = datetime.now().isoformat()

    # Clean up pending session data
    session.pop('pending_totp_secret', None)
    session.pop('pending_totp_enabled', None)
    session.pop('pending_security_question', None)
    session.pop('pending_security_answer', None)
    session.pop('auth_step', None)

    log_action('login_complete')


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
    create_api_blueprint(
        {
            'request_validator': RequestValidator,
            'login_request_model': LoginApiRequest,
            'query_request_model': QueryApiRequest,
            'table_path_model': TablePathParams,
            'table_pagination_model': TablePaginationParams,
            'health_response_model': HealthResponse,
            'session_response_model': SessionResponse,
            'totp_response_model': TotpCurrentResponse,
            'logout_response_model': LogoutResponse,
            'api_service_factory': api_service,
            'enable_totp_test_endpoint': runtime.config.enable_totp_test_endpoint,
            'get_db': get_db,
            'get_totp_token': runtime.totp_service.get_token,
            'login_required': login_required,
            'log_action': log_action,
        }
    )
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


if __name__ == '__main__':
    # Check if SSL certificates exist for HTTPS
    # Try Docker path first, then local path
    ssl_paths = [
        ('/app/certs/cert.pem', '/app/certs/key.pem'),  # Docker path
        ('certs/cert.pem', 'certs/key.pem'),  # Local path
    ]

    ssl_cert = None
    ssl_key = None

    for cert_path, key_path in ssl_paths:
        if os.path.exists(cert_path) and os.path.exists(key_path):
            ssl_cert = cert_path
            ssl_key = key_path
            break

    # Port to use (5000 in Docker, 5001 locally to avoid macOS AirPlay conflict)
    default_port = 5000 if os.path.exists('/app') else 5001
    PORT = int(os.environ.get('PORT', default_port))

    if ssl_cert and ssl_key:
        # Run with HTTPS
        logger.info("Starting server with HTTPS on port %s (cert: %s)...", PORT, ssl_cert)
        app.run(host='0.0.0.0', port=PORT, debug=runtime.config.debug_mode, ssl_context=(ssl_cert, ssl_key))
    else:
        # Fallback to HTTP (for development without certs)
        logger.info("SSL certificates not found. Starting server with HTTP on port %s...", PORT)
        app.run(host='0.0.0.0', port=PORT, debug=runtime.config.debug_mode)
