"""
Container 1: Database Server
A real database application with MVC architecture, SQLite database,
and multi-factor authentication (password + TOTP 2FA)
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g, abort
from functools import wraps
from datetime import datetime, timedelta
import importlib
import importlib.util
import secrets
import os
import hmac
import hashlib
import time
import logging
import sys
from pathlib import Path
from typing import Any, cast

from cachelib.file import FileSystemCache
from flask_session import Session
import redis as redis_lib
from werkzeug.middleware.proxy_fix import ProxyFix

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


_auth_module = _load_sibling_module("auth_utils")
_db_module = _load_sibling_module("db")
_api_schemas_module = _load_sibling_module("api_schemas")
_api_validation_module = _load_sibling_module("api_validation")
_api_services_module = _load_sibling_module("api_services")
_api_blueprint_module = _load_sibling_module("api_blueprint")

get_totp_token = _auth_module.get_totp_token
verify_totp = _auth_module.verify_totp
_verify_and_upgrade = _auth_module._verify_and_upgrade
connect_db = _db_module.connect_db
init_database = _db_module.init_db
db_list_tables = _db_module.list_tables
db_table_columns = _db_module.table_columns
LoginApiRequest = _api_schemas_module.LoginApiRequest
QueryApiRequest = _api_schemas_module.QueryApiRequest
RequestValidator = _api_validation_module.RequestValidator
RequestPayloadValidationError = _api_validation_module.RequestPayloadValidationError
DatabaseApiService = _api_services_module.DatabaseApiService
create_api_blueprint = _api_blueprint_module.create_api_blueprint
HealthResponse = _api_schemas_module.HealthResponse
SessionResponse = _api_schemas_module.SessionResponse
TotpCurrentResponse = _api_schemas_module.TotpCurrentResponse
LogoutResponse = _api_schemas_module.LogoutResponse
TablePathParams = _api_schemas_module.TablePathParams
TablePaginationParams = _api_schemas_module.TablePaginationParams

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['SESSION_COOKIE_NAME'] = 'db_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True

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
    setattr(app, "wsgi_app", ProxyFix(cast(Any, app.wsgi_app), x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1))
enable_totp_test_endpoint_env = os.environ.get('ENABLE_TOTP_TEST_ENDPOINT')
if enable_totp_test_endpoint_env is None:
    ENABLE_TOTP_TEST_ENDPOINT = DEMO_MODE
else:
    ENABLE_TOTP_TEST_ENDPOINT = enable_totp_test_endpoint_env.lower() == 'true'

enable_query_console_env = os.environ.get('ENABLE_QUERY_CONSOLE')
if enable_query_console_env is None:
    ENABLE_QUERY_CONSOLE = DEMO_MODE
else:
    ENABLE_QUERY_CONSOLE = enable_query_console_env.lower() == 'true'

def _ssl_cert_available():
    cert_paths = [
        '/app/certs/cert.pem',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs', 'cert.pem'),
    ]
    key_paths = [
        '/app/certs/key.pem',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs', 'key.pem'),
    ]
    return any(os.path.exists(p) for p in cert_paths) and any(os.path.exists(p) for p in key_paths)

cookie_secure_env = os.environ.get('SESSION_COOKIE_SECURE')
if cookie_secure_env is None:
    app.config['SESSION_COOKIE_SECURE'] = APP_ENV == 'production' or _ssl_cert_available()
else:
    app.config['SESSION_COOKIE_SECURE'] = cookie_secure_env.lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
if APP_ENV == 'production':
    app.config['PREFERRED_URL_SCHEME'] = 'https'

# Logging
logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'))
logger = logging.getLogger("database_server")

# Server-side sessions (Redis preferred)
REDIS_URL = os.environ.get('REDIS_URL')
if REDIS_URL:
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis_lib.from_url(REDIS_URL)
    app.config['SESSION_KEY_PREFIX'] = os.environ.get('SESSION_KEY_PREFIX', 'db_session:')
else:
    session_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sessions')
    os.makedirs(session_dir, exist_ok=True)
    app.config['SESSION_TYPE'] = 'cachelib'
    app.config['SESSION_CACHELIB'] = FileSystemCache(cache_dir=session_dir)
Session(app)

# Basic in-memory rate limiting (per-process)
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get('RATE_LIMIT_WINDOW_SECONDS', '600'))
RATE_LIMIT_MAX_ATTEMPTS = int(os.environ.get('RATE_LIMIT_MAX_ATTEMPTS', '5'))
_RATE_LIMITS: dict[str, dict[str, list[float]]] = {"login": {}}


def _client_ip():
    # ProxyFix normalizes REMOTE_ADDR from trusted forwarded headers.
    return request.remote_addr or 'unknown'


def _is_rate_limited(bucket):
    now = time.time()
    ip = _client_ip()
    attempts = [ts for ts in _RATE_LIMITS.get(bucket, {}).get(ip, []) if now - ts < RATE_LIMIT_WINDOW_SECONDS]
    _RATE_LIMITS.setdefault(bucket, {})[ip] = attempts
    return len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS


def _record_failed_attempt(bucket):
    now = time.time()
    ip = _client_ip()
    attempts = _RATE_LIMITS.setdefault(bucket, {}).setdefault(ip, [])
    attempts.append(now)


def _ensure_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': _ensure_csrf_token()}


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
    """Get database connection"""
    db = getattr(g, '_database', None)
    if db is None:
        # Per-request connection; schema is created at startup.
        db = g._database = connect_db(retries=1)
    return db


def _api_service() -> Any:
    return DatabaseApiService(
        session_store=cast(Any, session),
        get_db=get_db,
        db_list_tables=db_list_tables,
        db_table_columns=db_table_columns,
        verify_totp=verify_totp,
        verify_and_upgrade=_verify_and_upgrade,
        complete_login=complete_login,
        log_action=log_action,
        is_rate_limited=_is_rate_limited,
        record_failed_attempt=_record_failed_attempt,
        enable_query_console=ENABLE_QUERY_CONSOLE,
    )


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


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
        db = get_db()
        prev_row = db.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = prev_row['entry_hash'] if prev_row and prev_row['entry_hash'] else ''
        ts = datetime.utcnow().isoformat()
        payload = f"{prev_hash}|{ts}|{session['user_id']}|{action}|{table_name or ''}|{query or ''}"
        entry_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        db.execute(
            "INSERT INTO audit_log (user_id, action, table_name, query, prev_hash, entry_hash, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session['user_id'], action, table_name, query, prev_hash, entry_hash, ts)
        )
        db.commit()


# ==================== Views (Templates served) ====================

@app.route('/')
def index():
    """Home page - redirects to login or dashboard"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - Step 1: Username and Password"""
    error = None

    if request.method == 'POST':
        if _is_rate_limited('login'):
            error = 'Too many login attempts. Please try again later.'
            return render_template('login.html', error=error)

        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db()
        user = db.execute(
            "SELECT * FROM auth_users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and _verify_and_upgrade(db, user['id'], 'password', user['password'], password):
            # Store pending auth in session for 2FA/security verification
            session['pending_user_id'] = user['id']
            session['pending_username'] = user['username']
            session['pending_role'] = user['role']
            session['pending_totp_enabled'] = user['totp_enabled']
            session['auth_step'] = 'password_verified'

            # Step 2: 2FA if enabled
            if user['totp_enabled']:
                return redirect(url_for('verify_2fa'))

            # Step 3: Security question if configured
            if user['security_question']:
                return redirect(url_for('verify_security'))

            # No additional steps required
            complete_login()
            return redirect(url_for('dashboard'))
        else:
            _record_failed_attempt('login')
            error = 'Invalid username or password'

    return render_template('login.html', error=error)


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Step 2: Two-Factor Authentication (TOTP)"""
    if 'pending_user_id' not in session or session.get('auth_step') != 'password_verified':
        return redirect(url_for('login'))

    error = None

    if request.method == 'POST':
        if _is_rate_limited('login'):
            error = 'Too many attempts. Please try again later.'
            return render_template('verify_2fa.html', error=error,
                                  username=session.get('pending_username'))

        db = get_db()
        user = db.execute(
            "SELECT totp_secret, security_question FROM auth_users WHERE id = ?",
            (session.get('pending_user_id'),)
        ).fetchone()
        if not user:
            return redirect(url_for('login'))

        totp_code = request.form.get('totp_code', '').strip()

        # Server-side validation: require exactly 6 numeric digits
        if not totp_code or not totp_code.isdigit() or len(totp_code) != 6:
            error = 'Authentication code must be exactly 6 digits.'
        else:
            if verify_totp(user['totp_secret'], totp_code):
                session['auth_step'] = 'totp_verified'

                # Proceed to security question if configured
                if user['security_question']:
                    return redirect(url_for('verify_security'))

                # No security question, complete login
                complete_login()
                return redirect(url_for('dashboard'))
            else:
                _record_failed_attempt('login')
                error = 'Invalid authentication code. Please try again.'

    return render_template('verify_2fa.html', error=error,
                          username=session.get('pending_username'))


@app.route('/verify-security', methods=['GET', 'POST'])
def verify_security():
    """Step 3: Security Question Verification"""
    expected_step = 'totp_verified' if session.get('pending_totp_enabled') else 'password_verified'
    if 'pending_user_id' not in session or session.get('auth_step') != expected_step:
        return redirect(url_for('login'))

    error = None
    db = get_db()
    user = db.execute(
        "SELECT security_question, security_answer FROM auth_users WHERE id = ?",
        (session.get('pending_user_id'),)
    ).fetchone()
    if not user:
        return redirect(url_for('login'))

    question = user['security_question']

    # If no security question is configured, complete login
    if not question:
        complete_login()
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if _is_rate_limited('login'):
            error = 'Too many attempts. Please try again later.'
            return render_template('verify_security.html', error=error,
                                  question=question,
                                  username=session.get('pending_username'))

        answer = request.form.get('security_answer', '').strip()
        expected = user['security_answer'] or ''

        answer_norm = answer.lower()
        if _verify_and_upgrade(db, session.get('pending_user_id'), 'security_answer', expected, answer_norm):
            complete_login()
            return redirect(url_for('dashboard'))
        else:
            _record_failed_attempt('login')
            error = 'Incorrect security answer. Please try again.'

    return render_template('verify_security.html', error=error,
                          question=question,
                          username=session.get('pending_username'))


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


@app.route('/logout')
def logout():
    """Logout and clear session"""
    log_action('logout')
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    db = get_db()

    stats = {
        'employees': db.execute("SELECT COUNT(*) FROM employees").fetchone()[0],
        'departments': db.execute("SELECT COUNT(*) FROM departments").fetchone()[0],
        'projects': db.execute("SELECT COUNT(*) FROM projects WHERE status = 'active'").fetchone()[0],
        'total_salary': db.execute("SELECT SUM(salary) FROM employees WHERE is_active = ?", (True,)).fetchone()[0] or 0
    }

    recent_employees = db.execute(
        "SELECT * FROM employees ORDER BY hire_date DESC LIMIT 5"
    ).fetchall()

    return render_template('dashboard.html', stats=stats, recent_employees=recent_employees)


@app.route('/employees')
@login_required
def employees():
    """Employees list page"""
    db = get_db()
    employees_list = db.execute("SELECT * FROM employees ORDER BY name").fetchall()
    return render_template('employees.html', employees=employees_list)


@app.route('/departments')
@login_required
def departments():
    """Departments list page"""
    db = get_db()
    depts = db.execute("""
        SELECT d.*, COUNT(e.id) as employee_count 
        FROM departments d 
        LEFT JOIN employees e ON d.name = e.department 
        GROUP BY d.id
    """).fetchall()
    return render_template('departments.html', departments=depts)


@app.route('/projects')
@login_required
def projects():
    """Projects list page"""
    db = get_db()
    projects_list = db.execute("""
        SELECT p.*, d.name as department_name 
        FROM projects p 
        LEFT JOIN departments d ON p.department_id = d.id
        ORDER BY p.start_date DESC
    """).fetchall()
    return render_template('projects.html', projects=projects_list)


@app.route('/query')
@login_required
def query_page():
    """Query interface page"""
    if not ENABLE_QUERY_CONSOLE:
        return redirect(url_for('dashboard'))
    return render_template('query.html')


@app.route('/audit')
@login_required
def audit_log_page():
    """Audit log page - admin only"""
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))

    db = get_db()
    logs = db.execute("""
        SELECT a.*, u.username 
        FROM audit_log a 
        LEFT JOIN auth_users u ON a.user_id = u.id 
        ORDER BY a.timestamp DESC 
        LIMIT 100
    """).fetchall()
    return render_template('audit.html', logs=logs)


def verify_audit_chain():
    """Verify tamper-evident audit hash chain"""
    db = get_db()
    rows = db.execute(
        "SELECT id, user_id, action, table_name, query, prev_hash, entry_hash, timestamp FROM audit_log ORDER BY id"
    ).fetchall()
    prev_hash = ''
    for row in rows:
        payload = f"{prev_hash}|{row['timestamp']}|{row['user_id']}|{row['action']}|{row['table_name'] or ''}|{row['query'] or ''}"
        expected = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        if row['entry_hash'] != expected:
            return False, {'id': row['id'], 'expected': expected, 'actual': row['entry_hash']}
        prev_hash = row['entry_hash'] or ''
    return True, None


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
            'api_service_factory': _api_service,
            'enable_totp_test_endpoint': ENABLE_TOTP_TEST_ENDPOINT,
            'get_db': get_db,
            'get_totp_token': get_totp_token,
            'login_required': login_required,
            'log_action': log_action,
            'verify_audit_chain': verify_audit_chain,
        }
    )
)


# Initialize database on startup
with app.app_context():
    bootstrap_db = connect_db(retries=int(os.environ.get("DB_CONNECT_RETRIES", "30")))
    init_database(
        bootstrap_db,
        demo_mode=DEMO_MODE,
        enable_totp_test_endpoint=ENABLE_TOTP_TEST_ENDPOINT,
        log_info=logger.info,
    )
    bootstrap_db.close()


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
        app.run(host='0.0.0.0', port=PORT, debug=DEBUG_MODE, ssl_context=(ssl_cert, ssl_key))
    else:
        # Fallback to HTTP (for development without certs)
        logger.info("SSL certificates not found. Starting server with HTTP on port %s...", PORT)
        app.run(host='0.0.0.0', port=PORT, debug=DEBUG_MODE)
