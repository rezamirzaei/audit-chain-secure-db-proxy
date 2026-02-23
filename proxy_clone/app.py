"""
Container 2: Proxy Gateway (demo mode optional)
- Has its own HOME interface for end users to write queries
- Can clone/mirror the original database server UI dynamically (demo only)
- Handles multi-step authentication in demo mode
- Proxies requests transparently
- Connects to database server via HTTPS
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, abort
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


# ==================== HOME Interface (Proxy's own UI) ====================

@app.route('/')
def home():
    """Proxy's home page - query interface for end users"""
    if not runtime.config.proxy_features_enabled:
        return jsonify({'error': 'Proxy demo features are disabled in production'}), 404
    status = vault.get_status()
    return render_template('home.html', status=status)


@app.route('/connect', methods=['GET', 'POST'])
@feature_enabled
def connect():
    """Page to capture/enter credentials - handles multi-step auth"""
    error = None
    status = vault.get_status()

    # Get step from URL args (GET) or form (POST)
    if request.method == 'GET':
        step = request.args.get('step', 'credentials')
    else:
        step = request.form.get('step', 'credentials')

    # Debug logging
    _debug("connect() called - method=%s, step=%s", request.method, step)
    _debug("vault.auth_state = %s", vault.auth_state)
    _debug("vault.credentials = %s", bool(vault.credentials))

    if step in ['totp', 'security'] and not vault.credentials:
        return redirect(url_for('connect', step='credentials'))

    if request.method == 'POST':
        if step == 'credentials':
            username = request.form.get('username')
            password = request.form.get('password')

            # Store the credentials (this is the "breach")
            vault.store_credentials(username, password)

            # Reset auth state for fresh login
            vault.auth_state = {}

            # Try to login - Step 1
            result = vault.login()
            _debug("credentials login result: %s", result)

            if result.get('success'):
                return redirect(url_for('home'))
            elif result.get('requires_totp'):
                # Need 2FA code - redirect to step 2
                _debug("Redirecting to totp step, auth_state = %s", vault.auth_state)
                return redirect(url_for('connect', step='totp'))
            elif result.get('requires_security'):
                # Need security answer - redirect to step 3
                session['security_question'] = result.get('security_question')
                return redirect(url_for('connect', step='security'))
            else:
                error = result.get('error', 'Failed to connect')

        elif step == 'totp':
            totp_code = request.form.get('totp_code', '').strip()
            _debug("totp step - totp_code=%s, auth_state=%s", totp_code, vault.auth_state)

            # Server-side validation: require 6 digits
            if not totp_code:
                error = 'Please enter the 2FA code'
            elif not totp_code.isdigit() or len(totp_code) != 6:
                error = '2FA code must be exactly 6 digits'
            else:
                # Continue auth with TOTP - Step 2
                result = vault.login(totp_code=totp_code)
                _debug("totp login result: %s", result)

                if result.get('success'):
                    return redirect(url_for('home'))
                elif result.get('requires_security'):
                    session['security_question'] = result.get('security_question')
                    return redirect(url_for('connect', step='security'))
                else:
                    error = result.get('error', 'Invalid 2FA code')
                    # Stay on TOTP step to retry

        elif step == 'security':
            security_answer = request.form.get('security_answer', '').strip()

            if not security_answer:
                error = 'Please enter your security answer'
            else:
                # Continue auth with security answer - Step 3
                result = vault.login(security_answer=security_answer)
                _debug("security login result: %s", result)

                if result.get('success'):
                    return redirect(url_for('home'))
                else:
                    error = result.get('error', 'Invalid security answer')
                    # Stay on security step to retry

    # Get security question from session or vault
    security_question = session.get('security_question') or vault.auth_state.get('security_question')

    return render_template('connect.html',
                          error=error,
                          status=status,
                          step=step,
                          security_question=security_question)


@app.route('/disconnect', methods=['POST'])
@feature_enabled
def disconnect():
    """Clear stored credentials and all captured auth info"""
    vault.reset_auth(clear_credentials=True)
    _drop_current_vault()
    session.pop('security_question', None)
    return redirect(url_for('connect'))


# ==================== Clone/Mirror Original UI ====================

@app.route('/mirror/')
@app.route('/mirror/<path:path>')
@feature_enabled
@proxy_authenticated
def mirror(path=''):
    """
    Mirror/Clone the original database server UI dynamically.
    Fetches pages from the database server and serves them through the proxy.
    """
    # Proxy the request to the database server
    response = vault.proxy_request('GET', f'/{path}')

    if response is None:
        return "Failed to connect to database server", 503

    # Get the content
    content = response.content
    content_type = response.headers.get('Content-Type', 'text/html')

    # If it's HTML, we can optionally modify it (add proxy banner, etc.)
    if 'text/html' in content_type:
        content = content.decode('utf-8')

        # Add a banner to show this is the mirrored version
        banner = '''
        <div style="position:fixed;top:0;left:0;right:0;background:linear-gradient(90deg,#dc3545,#c82333);
                    color:white;text-align:center;padding:8px;z-index:9999;font-size:14px;">
            <i class="bi bi-shield-exclamation"></i>
            <strong>PROXY MIRROR</strong> - You are viewing through the proxy gateway
            <a href="/" style="color:white;margin-left:20px;">← Back to Proxy Home</a>
        </div>
        <style>body{margin-top:40px !important;}.sidebar{top:40px !important;height:calc(100vh - 40px) !important;}</style>
        '''

        # Insert banner after <body> tag
        content = content.replace('<body>', f'<body>{banner}')

        # Rewrite links to go through the mirror
        content = content.replace('href="/', 'href="/mirror/')
        content = content.replace("href='/", "href='/mirror/")
        content = content.replace('action="/', 'action="/mirror/')

        content = content.encode('utf-8')

    return Response(content, content_type=content_type, status=response.status_code)


@app.route('/mirror/api/<path:path>', methods=['GET', 'POST'])
@feature_enabled
@proxy_authenticated
def mirror_api(path):
    """Mirror API calls to the database server"""
    if request.method == 'POST':
        response = vault.proxy_request('POST', f'/api/{path}', json=request.get_json())
    else:
        response = vault.proxy_request('GET', f'/api/{path}')

    if response is None:
        return jsonify({'error': 'Failed to connect to database server'}), 503

    return Response(
        response.content,
        content_type=response.headers.get('Content-Type'),
        status=response.status_code
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
