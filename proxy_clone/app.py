"""
Container 2: Proxy Gateway (demo mode optional)
- Has its own HOME interface for end users to write queries
- Can clone/mirror the original database server UI dynamically (demo only)
- Handles multi-step authentication in demo mode
- Proxies requests transparently
- Connects to database server via HTTPS
"""

from flask import Flask, request, jsonify, session, redirect, url_for, abort
from functools import wraps
import secrets
import os
import hmac
from typing import Any
from werkzeug.local import LocalProxy

from .api_schemas import ConnectApiRequest, QueryApiRequest, TablePathParams
from .api_validation import RequestValidator, RequestPayloadValidationError
from .api_services import ProxyApiService
from .api_blueprint import create_api_blueprint
from .runtime import ProxyCloneRuntime
from .state.credential_vault import CredentialVault
from .state.vault_registry import VaultRegistry
from .web_routes import register_web_routes

runtime = ProxyCloneRuntime()
app = runtime.app
logger = runtime.logger

def _debug(msg, *args):
    if runtime.config.debug_mode:
        logger.debug(msg, *args)


def _ensure_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': _ensure_csrf_token(), 'demo_mode': runtime.config.demo_mode}


@app.before_request
def enforce_csrf():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
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

def _new_vault() -> CredentialVault:
    return CredentialVault(
        database_server_url=runtime.config.database_server_url,
        ssl_verify=runtime.config.ssl_verify,
        debug_log=_debug,
    )


vault_registry = VaultRegistry(factory=_new_vault)
_VAULTS = vault_registry.vaults


def _current_vault() -> CredentialVault:
    return vault_registry.current(session)


def _drop_current_vault() -> None:
    vault_registry.drop_current(session)


vault = LocalProxy(_current_vault)


def _proxy_api_service() -> Any:
    return ProxyApiService(vault=vault, demo_mode=runtime.config.demo_mode)


def feature_enabled(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not runtime.config.proxy_features_enabled:
            abort(404)
        return f(*args, **kwargs)
    return decorated


def proxy_authenticated(f):
    """Decorator to ensure proxy has valid credentials"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not vault.credentials:
            return redirect(url_for('connect'))
        if not vault.ensure_session():
            next_step = vault.auth_state.get('current_step')
            if next_step == 'waiting_totp':
                return redirect(url_for('connect', step='totp'))
            if next_step == 'waiting_security':
                return redirect(url_for('connect', step='security'))
            return redirect(url_for('connect'))
        return f(*args, **kwargs)
    return decorated_function


def proxy_status_available(f):
    """Decorator for API status access after a proxy session has captured credentials."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not vault.credentials:
            return jsonify({'error': 'Not connected'}), 401
        return f(*args, **kwargs)
    return decorated_function


register_web_routes(
    app,
    {
        "vault": vault,
        "feature_enabled": feature_enabled,
        "proxy_authenticated": proxy_authenticated,
        "drop_current_vault": _drop_current_vault,
        "debug": _debug,
        "proxy_features_enabled": runtime.config.proxy_features_enabled,
    },
)


app.register_blueprint(
    create_api_blueprint(
        {
            'request_validator': RequestValidator,
            'connect_request_model': ConnectApiRequest,
            'query_request_model': QueryApiRequest,
            'table_path_model': TablePathParams,
            'api_service_factory': _proxy_api_service,
            'feature_enabled': feature_enabled,
            'proxy_status_available': proxy_status_available,
            'vault': vault,
        }
    )
)


def create_app() -> Flask:
    """Application factory entrypoint for WSGI servers and tests."""
    return app


if __name__ == '__main__':
    # Check if SSL certificates exist for HTTPS
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

    PORT = int(os.environ.get('PORT', 8080))

    if ssl_cert and ssl_key:
        logger.info("Starting proxy with HTTPS on port %s (cert: %s)...", PORT, ssl_cert)
        app.run(host='0.0.0.0', port=PORT, debug=runtime.config.debug_mode, ssl_context=(ssl_cert, ssl_key))
    else:
        logger.info("SSL certificates not found. Starting proxy with HTTP on port %s...", PORT)
        app.run(host='0.0.0.0', port=PORT, debug=runtime.config.debug_mode)
