"""
Container 2: Proxy Gateway (demo mode optional)
- Has its own HOME interface for end users to write queries
- Can clone/mirror the original database server UI dynamically (demo only)
- Handles multi-step authentication in demo mode
- Proxies requests transparently
- Connects to database server via HTTPS
"""

from flask import Flask, jsonify, session, redirect, url_for, abort
from functools import wraps
import os
from typing import Any
from werkzeug.local import LocalProxy

from .api_schemas import ConnectApiRequest, QueryApiRequest, TablePathParams
from .api_validation import RequestValidator, RequestPayloadValidationError
from .api_services import ProxyApiService
from .api_blueprint import ProxyApiBlueprintDependencies, create_api_blueprint
from .runtime import ProxyCloneRuntime
from .state.credential_vault import CredentialVault
from .state.vault_registry import VaultRegistry
from .web_routes import ProxyWebRouteDependencies, register_web_routes
from .ssl_utils import get_ssl_context
from .common import (
    SecurityHeadersManager,
    ContextInjector,
    enforce_csrf,
    handle_request_validation_error,
)

runtime = ProxyCloneRuntime()
app = runtime.app
logger = runtime.logger

def debug_log(msg, *args):
    if runtime.config.debug_mode:
        logger.debug(msg, *args)


@app.context_processor
def inject_csrf_token():
    return ContextInjector.inject_base_context(demo_mode=runtime.config.demo_mode)


@app.before_request
def before_request_handlers() -> None:
    """Register before-request handlers."""
    enforce_csrf()


@app.after_request
def after_request_handlers(response: Any) -> Any:
    """Register after-request handlers."""
    return SecurityHeadersManager.set_security_headers(app)(response)


@app.errorhandler(RequestPayloadValidationError)
def handle_validation_error(error: RequestPayloadValidationError) -> tuple[dict[str, Any], int]:
    """Handle request validation errors."""
    return handle_request_validation_error(error)

def create_vault_instance() -> CredentialVault:
    return CredentialVault(
        database_server_url=runtime.config.database_server_url,
        ssl_verify=runtime.config.ssl_verify,
        debug_log=debug_log,
    )


vault_registry = VaultRegistry(factory=create_vault_instance)
_VAULTS = vault_registry.vaults


def current_vault() -> CredentialVault:
    return vault_registry.current(session)


def drop_current_vault() -> None:
    vault_registry.drop_current(session)


vault = LocalProxy(current_vault)


def proxy_api_service() -> Any:
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
    ProxyWebRouteDependencies(
        vault=vault,
        feature_enabled=feature_enabled,
        proxy_authenticated=proxy_authenticated,
        drop_current_vault=drop_current_vault,
        debug=debug_log,
        proxy_features_enabled=runtime.config.proxy_features_enabled,
    ),
)


app.register_blueprint(
    create_api_blueprint(
        ProxyApiBlueprintDependencies(
            request_validator=RequestValidator,
            connect_request_model=ConnectApiRequest,
            query_request_model=QueryApiRequest,
            table_path_model=TablePathParams,
            api_service_factory=proxy_api_service,
            feature_enabled=feature_enabled,
            proxy_status_available=proxy_status_available,
            vault=vault,
        )
    )
)


def create_app() -> Flask:
    """Application factory entrypoint for WSGI servers and tests."""
    return app


if __name__ == '__main__':
    # Get SSL certificates if available
    ssl_cert, ssl_key = get_ssl_context()

    PORT = int(os.environ.get('PORT', 8080))

    # Start server with or without HTTPS
    if ssl_cert and ssl_key:
        logger.info("Starting proxy with HTTPS on port %s (cert: %s)...", PORT, ssl_cert)
        app.run(host='0.0.0.0', port=PORT, debug=runtime.config.debug_mode, ssl_context=(ssl_cert, ssl_key))
    else:
        logger.info("SSL certificates not found. Starting proxy with HTTP on port %s...", PORT)
        app.run(host='0.0.0.0', port=PORT, debug=runtime.config.debug_mode)
