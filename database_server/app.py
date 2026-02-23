"""
Container 1: Database Server
A real database application with MVC architecture, SQLite database,
and multi-factor authentication (password + TOTP 2FA)
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g, abort
from functools import wraps
from datetime import datetime, timedelta
import secrets
import os
import hmac
import time
import logging
from typing import Any, cast

from cachelib.file import FileSystemCache
from flask_session import Session
import redis as redis_lib
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import func, select
from sqlalchemy.orm import aliased

from .auth_utils import PasswordService, TotpService
from .db import DatabaseSessionManager, init_db as init_database
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
from .models import AuthUser, AuditLog, Department, Employee, Project

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

# Database session manager (SQLAlchemy)
db_manager = DatabaseSessionManager.from_env()
password_service = PasswordService()
totp_service = TotpService()

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
    """Get SQLAlchemy session for this request."""
    db_session = getattr(g, '_db_session', None)
    if db_session is None:
        db_session = g._db_session = db_manager.session()
    return db_session


def _api_service() -> Any:
    db_session = get_db()
    return DatabaseApiService(
        session_store=cast(Any, session),
        db_session=db_session,
        user_service=UserService(db_session),
        audit_service=AuditService(db_session),
        schema_service=SchemaService(db_manager.engine),
        query_service=QueryService(db_session),
        table_service=TableService(db_session),
        password_service=password_service,
        totp_service=totp_service,
        complete_login=complete_login,
        is_rate_limited=_is_rate_limited,
        record_failed_attempt=_record_failed_attempt,
        enable_query_console=ENABLE_QUERY_CONSOLE,
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
        service = _api_service()
        service.audit_service.log_action(
            user_id=session['user_id'],
            action=action,
            table_name=table_name,
            query=query,
        )


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

        db_session = get_db()
        user_service = UserService(db_session)
        user = user_service.get_by_username(username or "")

        if user and password_service.verify_and_upgrade(db_session, user, "password", password):
            # Store pending auth in session for 2FA/security verification
            session['pending_user_id'] = user.id
            session['pending_username'] = user.username
            session['pending_role'] = user.role
            session['pending_totp_enabled'] = user.totp_enabled
            session['auth_step'] = 'password_verified'

            # Step 2: 2FA if enabled
            if user.totp_enabled:
                return redirect(url_for('verify_2fa'))

            # Step 3: Security question if configured
            if user.security_question:
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

        db_session = get_db()
        user_service = UserService(db_session)
        user = user_service.get_by_id(int(session.get('pending_user_id')))
        if not user:
            return redirect(url_for('login'))

        totp_code = request.form.get('totp_code', '').strip()

        # Server-side validation: require exactly 6 numeric digits
        if not totp_code or not totp_code.isdigit() or len(totp_code) != 6:
            error = 'Authentication code must be exactly 6 digits.'
        else:
            if user.totp_secret and totp_service.verify(user.totp_secret, totp_code):
                session['auth_step'] = 'totp_verified'

                # Proceed to security question if configured
                if user.security_question:
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
    db_session = get_db()
    user_service = UserService(db_session)
    user = user_service.get_by_id(int(session.get('pending_user_id')))
    if not user:
        return redirect(url_for('login'))

    question = user.security_question

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
        answer_norm = answer.lower()
        if password_service.verify_and_upgrade(db_session, user, 'security_answer', answer_norm):
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
    db_session = get_db()

    stats = {
        'employees': db_session.execute(select(func.count(Employee.id))).scalar_one(),
        'departments': db_session.execute(select(func.count(Department.id))).scalar_one(),
        'projects': db_session.execute(
            select(func.count(Project.id)).where(Project.status == 'active')
        ).scalar_one(),
        'total_salary': db_session.execute(
            select(func.sum(Employee.salary)).where(Employee.is_active.is_(True))
        ).scalar_one() or 0,
    }

    recent_employees = db_session.execute(
        select(Employee).order_by(Employee.hire_date.desc()).limit(5)
    ).scalars().all()

    return render_template('dashboard.html', stats=stats, recent_employees=recent_employees)


@app.route('/employees')
@login_required
def employees():
    """Employees list page"""
    db_session = get_db()
    dept_filter = request.args.get('dept')
    stmt = select(Employee).order_by(Employee.name)
    if dept_filter:
        stmt = stmt.where(Employee.department == dept_filter)
    employees_list = db_session.execute(stmt).scalars().all()
    return render_template('employees.html', employees=employees_list)


@app.route('/departments')
@login_required
def departments():
    """Departments list page"""
    db_session = get_db()
    employee_alias = aliased(Employee)
    rows = db_session.execute(
        select(
            Department,
            func.count(employee_alias.id).label("employee_count"),
        )
        .outerjoin(employee_alias, Department.name == employee_alias.department)
        .group_by(Department.id)
        .order_by(Department.name)
    ).all()
    departments_payload = [
        {
            "id": dept.id,
            "name": dept.name,
            "budget": dept.budget or 0,
            "employee_count": int(employee_count or 0),
        }
        for dept, employee_count in rows
    ]
    return render_template('departments.html', departments=departments_payload)


@app.route('/projects')
@login_required
def projects():
    """Projects list page"""
    db_session = get_db()
    dept_alias = aliased(Department)
    rows = db_session.execute(
        select(
            Project,
            dept_alias.name.label("department_name"),
        )
        .outerjoin(dept_alias, Project.department_id == dept_alias.id)
        .order_by(Project.start_date.desc())
    ).all()
    projects_payload = [
        {
            "id": project.id,
            "name": project.name,
            "description": project.description or "",
            "department_name": department_name,
            "start_date": project.start_date,
            "end_date": project.end_date,
            "status": project.status,
        }
        for project, department_name in rows
    ]
    return render_template('projects.html', projects=projects_payload)


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

    db_session = get_db()
    rows = db_session.execute(
        select(AuditLog, AuthUser.username)
        .outerjoin(AuthUser, AuditLog.user_id == AuthUser.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(100)
    ).all()
    logs = [
        {
            "id": log.id,
            "username": username,
            "action": log.action,
            "table_name": log.table_name,
            "query": log.query,
            "timestamp": log.timestamp,
        }
        for log, username in rows
    ]
    return render_template('audit.html', logs=logs)


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
            'get_totp_token': totp_service.get_token,
            'login_required': login_required,
            'log_action': log_action,
        }
    )
)


# Initialize database on startup
with app.app_context():
    init_database(
        db_manager,
        demo_mode=DEMO_MODE,
        enable_totp_test_endpoint=ENABLE_TOTP_TEST_ENDPOINT,
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
        app.run(host='0.0.0.0', port=PORT, debug=DEBUG_MODE, ssl_context=(ssl_cert, ssl_key))
    else:
        # Fallback to HTTP (for development without certs)
        logger.info("SSL certificates not found. Starting server with HTTP on port %s...", PORT)
        app.run(host='0.0.0.0', port=PORT, debug=DEBUG_MODE)
