"""
Container 1: Database Server
A real database application with MVC architecture, SQLite database,
and multi-factor authentication (password + TOTP 2FA)
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g, abort
from functools import wraps
from datetime import datetime, timedelta
import sqlite3
import secrets
import os
import hmac
import hashlib
import struct
import time
import base64
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
import redis as redis_lib
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['SESSION_COOKIE_NAME'] = 'db_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Environment / feature flags
APP_ENV = os.environ.get('APP_ENV', 'production').lower()
DEMO_MODE = APP_ENV != 'production'
DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
TRUST_PROXY = os.environ.get('TRUST_PROXY')
if TRUST_PROXY is None:
    TRUST_PROXY = APP_ENV == 'production'
else:
    TRUST_PROXY = TRUST_PROXY.lower() == 'true'

if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
ENABLE_TOTP_TEST_ENDPOINT = os.environ.get('ENABLE_TOTP_TEST_ENDPOINT')
if ENABLE_TOTP_TEST_ENDPOINT is None:
    ENABLE_TOTP_TEST_ENDPOINT = DEMO_MODE
else:
    ENABLE_TOTP_TEST_ENDPOINT = ENABLE_TOTP_TEST_ENDPOINT.lower() == 'true'

ENABLE_QUERY_CONSOLE = os.environ.get('ENABLE_QUERY_CONSOLE')
if ENABLE_QUERY_CONSOLE is None:
    ENABLE_QUERY_CONSOLE = DEMO_MODE
else:
    ENABLE_QUERY_CONSOLE = ENABLE_QUERY_CONSOLE.lower() == 'true'

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
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sessions')
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
app.config['SESSION_USE_SIGNER'] = True
Session(app)

# Basic in-memory rate limiting (per-process)
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get('RATE_LIMIT_WINDOW_SECONDS', '600'))
RATE_LIMIT_MAX_ATTEMPTS = int(os.environ.get('RATE_LIMIT_MAX_ATTEMPTS', '5'))
_RATE_LIMITS = {"login": {}}


def _client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
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

# Database path - use /app/data in Docker, local 'data' folder otherwise
if os.path.exists('/app'):
    DATABASE = '/app/data/database.db'
else:
    # Local development - use a 'data' folder in the script directory
    DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'database.db')


# ==================== TOTP (Time-based One-Time Password) Implementation ====================

def generate_totp_secret():
    """Generate a random TOTP secret"""
    return base64.b32encode(secrets.token_bytes(20)).decode('utf-8')


def get_totp_token(secret, time_step=30):
    """Generate current TOTP token"""
    # Decode the base32 secret
    key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))

    # Get current time step
    counter = int(time.time() // time_step)

    # Pack counter as big-endian 8-byte integer
    counter_bytes = struct.pack('>Q', counter)

    # Generate HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
    code = (code & 0x7FFFFFFF) % 1000000

    return str(code).zfill(6)


def verify_totp(secret, token, window=1):
    """Verify TOTP token with time window tolerance"""
    for i in range(-window, window + 1):
        # Check tokens from (current - window) to (current + window) time steps
        counter = int(time.time() // 30) + i

        key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
        counter_bytes = struct.pack('>Q', counter)
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

        offset = hmac_hash[-1] & 0x0F
        code = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
        code = (code & 0x7FFFFFFF) % 1000000
        expected = str(code).zfill(6)

        if token == expected:
            return True
    return False


def get_totp_uri(secret, username, issuer="DataVault"):
    """Generate otpauth URI for QR code"""
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"


_password_hasher = PasswordHasher()


def _is_hash(value):
    if not value:
        return False
    return value.startswith(('pbkdf2:', 'scrypt:', 'argon2:', '$argon2'))


def _is_argon2(value):
    return bool(value) and value.startswith('$argon2')


def _hash_value(value):
    return _password_hasher.hash(value)


def _verify_value(stored, provided):
    if stored is None or provided is None:
        return False, False

    if _is_argon2(stored):
        try:
            ok = _password_hasher.verify(stored, provided)
            return ok, _password_hasher.check_needs_rehash(stored) if ok else False
        except argon2_exceptions.VerifyMismatchError:
            return False, False
        except Exception:
            return False, False

    if _is_hash(stored):
        ok = check_password_hash(stored, provided)
        return ok, ok

    ok = hmac.compare_digest(stored, provided)
    return ok, ok


def _verify_and_upgrade(db, user_id, field, stored, provided):
    ok, needs_upgrade = _verify_value(stored, provided)
    if ok and needs_upgrade:
        db.execute(
            f"UPDATE auth_users SET {field} = ? WHERE id = ?",
            (_hash_value(provided), user_id)
        )
        db.commit()
    return ok


def get_db():
    """Get database connection"""
    db = getattr(g, '_database', None)
    if db is None:
        os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database with tables and sample data"""
    db = get_db()
    cursor = db.cursor()

    # Create users table for authentication with 2FA support
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            totp_secret TEXT,
            totp_enabled BOOLEAN DEFAULT 1,
            security_question TEXT,
            security_answer TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Ensure auth_users has all required columns (for existing DBs)
    cursor.execute("PRAGMA table_info(auth_users)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    required_cols = {
        'role': "TEXT DEFAULT 'user'",
        'totp_secret': "TEXT",
        'totp_enabled': "BOOLEAN DEFAULT 1",
        'security_question': "TEXT",
        'security_answer': "TEXT",
        'created_at': "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    }
    for col, definition in required_cols.items():
        if col not in existing_cols:
            cursor.execute(f"ALTER TABLE auth_users ADD COLUMN {col} {definition}")

    # Create sample data tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            department TEXT,
            salary REAL,
            hire_date DATE,
            is_active BOOLEAN DEFAULT 1
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            budget REAL,
            manager_id INTEGER,
            FOREIGN KEY (manager_id) REFERENCES employees(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            department_id INTEGER,
            start_date DATE,
            end_date DATE,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (department_id) REFERENCES departments(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            table_name TEXT,
            query TEXT,
            prev_hash TEXT,
            entry_hash TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Ensure audit_log has tamper-evident hash columns
    cursor.execute("PRAGMA table_info(audit_log)")
    audit_cols = {row[1] for row in cursor.fetchall()}
    if 'prev_hash' not in audit_cols:
        cursor.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
    if 'entry_hash' not in audit_cols:
        cursor.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")

    # Backfill audit hashes for existing rows
    cursor.execute("SELECT id, user_id, action, table_name, query, timestamp, entry_hash FROM audit_log ORDER BY id")
    rows = cursor.fetchall()
    if rows and any(row['entry_hash'] is None for row in rows):
        prev_hash = ''
        for row in rows:
            payload = f"{prev_hash}|{row['timestamp']}|{row['user_id']}|{row['action']}|{row['table_name'] or ''}|{row['query'] or ''}"
            entry_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
            cursor.execute(
                "UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?",
                (prev_hash, entry_hash, row['id'])
            )
            prev_hash = entry_hash

    # Insert default admin user if not exists (with 2FA)
    cursor.execute("SELECT COUNT(*) FROM auth_users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        # Generate TOTP secrets for users
        admin_secret = generate_totp_secret()
        analyst_secret = generate_totp_secret()
        admin_password = _hash_value('SecurePass123!')
        analyst_password = _hash_value('AnalystPass456!')
        admin_answer = _hash_value('blue')
        analyst_answer = _hash_value('fluffy')

        cursor.execute("""
            INSERT INTO auth_users (username, password, role, totp_secret, totp_enabled, security_question, security_answer) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ('admin', admin_password, 'admin', admin_secret, 1, 'What is your favorite color?', admin_answer))

        cursor.execute("""
            INSERT INTO auth_users (username, password, role, totp_secret, totp_enabled, security_question, security_answer) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ('analyst', analyst_password, 'analyst', analyst_secret, 1, 'What is your pet name?', analyst_answer))

        # Print TOTP secrets for testing (in real app, this would be shown to user during setup)
        if DEMO_MODE or ENABLE_TOTP_TEST_ENDPOINT:
            logger.info("=== 2FA SETUP ===")
            logger.info("Admin TOTP Secret: %s", admin_secret)
            logger.info("Admin Current Token: %s", get_totp_token(admin_secret))
            logger.info("Analyst TOTP Secret: %s", analyst_secret)
            logger.info("Analyst Current Token: %s", get_totp_token(analyst_secret))
            logger.info("==================")
    else:
        # Ensure existing users have required security data and TOTP secrets
        cursor.execute("UPDATE auth_users SET totp_enabled = 1 WHERE totp_enabled IS NULL")

        # Populate missing TOTP secrets
        cursor.execute("SELECT id, username FROM auth_users WHERE totp_secret IS NULL OR totp_secret = ''")
        missing_totp = cursor.fetchall()
        for user_id, username in missing_totp:
            secret = generate_totp_secret()
            cursor.execute("UPDATE auth_users SET totp_secret = ? WHERE id = ?", (secret, user_id))
            if DEMO_MODE:
                logger.info("[MIGRATION] Generated TOTP secret for %s: %s", username, secret)

        # Populate missing security questions/answers for default users
        cursor.execute("SELECT id, username, password, security_question, security_answer FROM auth_users")
        for user_id, username, password, question, answer in cursor.fetchall():
            # Hash plaintext passwords
            if password and not _is_hash(password):
                cursor.execute(
                    "UPDATE auth_users SET password = ? WHERE id = ?",
                    (_hash_value(password), user_id)
                )

            # Ensure default security questions/answers are set and hashed
            if username == 'admin' and (not question or not answer):
                cursor.execute(
                    "UPDATE auth_users SET security_question = ?, security_answer = ? WHERE id = ?",
                    ('What is your favorite color?', _hash_value('blue'), user_id)
                )
            elif username == 'analyst' and (not question or not answer):
                cursor.execute(
                    "UPDATE auth_users SET security_question = ?, security_answer = ? WHERE id = ?",
                    ('What is your pet name?', _hash_value('fluffy'), user_id)
                )
            elif answer and not _is_hash(answer):
                cursor.execute(
                    "UPDATE auth_users SET security_answer = ? WHERE id = ?",
                    (_hash_value(answer.lower()), user_id)
                )

    # Insert sample data if not exists
    cursor.execute("SELECT COUNT(*) FROM departments")
    if cursor.fetchone()[0] == 0:
        departments = [
            ('Engineering', 500000, None),
            ('Marketing', 200000, None),
            ('Sales', 300000, None),
            ('Human Resources', 150000, None),
            ('Finance', 250000, None)
        ]
        cursor.executemany("INSERT INTO departments (name, budget, manager_id) VALUES (?, ?, ?)", departments)

        employees = [
            ('John Smith', 'john.smith@company.com', 'Engineering', 95000, '2020-01-15', 1),
            ('Sarah Johnson', 'sarah.j@company.com', 'Engineering', 105000, '2019-06-01', 1),
            ('Mike Wilson', 'mike.w@company.com', 'Marketing', 75000, '2021-03-20', 1),
            ('Emily Davis', 'emily.d@company.com', 'Sales', 85000, '2020-08-10', 1),
            ('Robert Brown', 'robert.b@company.com', 'Finance', 90000, '2018-11-05', 1),
            ('Lisa Anderson', 'lisa.a@company.com', 'Human Resources', 70000, '2021-01-10', 1),
            ('David Martinez', 'david.m@company.com', 'Engineering', 115000, '2017-04-22', 1),
            ('Jennifer Taylor', 'jennifer.t@company.com', 'Marketing', 80000, '2020-09-15', 1),
            ('James Thomas', 'james.t@company.com', 'Sales', 95000, '2019-02-28', 1),
            ('Amanda White', 'amanda.w@company.com', 'Finance', 100000, '2018-07-01', 1),
        ]
        cursor.executemany(
            "INSERT INTO employees (name, email, department, salary, hire_date, is_active) VALUES (?, ?, ?, ?, ?, ?)",
            employees
        )

        projects = [
            ('Website Redesign', 'Complete overhaul of company website', 1, '2024-01-01', '2024-06-30', 'active'),
            ('Mobile App', 'Develop iOS and Android apps', 1, '2024-03-01', '2024-12-31', 'active'),
            ('Q1 Campaign', 'Spring marketing campaign', 2, '2024-01-15', '2024-03-31', 'completed'),
            ('Sales Expansion', 'Expand to new markets', 3, '2024-02-01', '2024-08-31', 'active'),
            ('HR System', 'New HR management system', 4, '2024-04-01', '2024-10-31', 'planning'),
        ]
        cursor.executemany(
            "INSERT INTO projects (name, description, department_id, start_date, end_date, status) VALUES (?, ?, ?, ?, ?, ?)",
            projects
        )

    db.commit()


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
        'total_salary': db.execute("SELECT SUM(salary) FROM employees WHERE is_active = 1").fetchone()[0] or 0
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


# ==================== API Endpoints ====================

@app.route('/api/health')
def api_health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected'
    })


@app.route('/api/session')
def api_session():
    """Get current session info"""
    if 'user_id' not in session:
        return jsonify({'authenticated': False})

    return jsonify({
        'authenticated': True,
        'user_id': session['user_id'],
        'username': session['username'],
        'role': session['role'],
        'login_time': session.get('login_time')
    })


@app.route('/api/login', methods=['POST'])
def api_login():
    """API login endpoint - supports multi-step authentication"""
    data = request.get_json() or {}
    step = data.get('step', 'password')  # password, totp, security

    if _is_rate_limited('login'):
        return jsonify({'error': 'Too many login attempts. Please try again later.'}), 429

    if step == 'password':
        # Step 1: Verify username and password
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Missing credentials'}), 400

        db = get_db()
        user = db.execute(
            "SELECT * FROM auth_users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and _verify_and_upgrade(db, user['id'], 'password', user['password'], password):
            # Store pending auth info
            session['pending_user_id'] = user['id']
            session['pending_username'] = user['username']
            session['pending_role'] = user['role']
            session['pending_totp_enabled'] = user['totp_enabled']
            session['auth_step'] = 'password_verified'

            if user['totp_enabled']:
                return jsonify({
                    'success': True,
                    'next_step': 'totp',
                    'message': 'Password verified. Please provide 2FA code.',
                    'requires_2fa': True
                })
            else:
                # No 2FA required, check if security question needed
                if user['security_question']:
                    return jsonify({
                        'success': True,
                        'next_step': 'security',
                        'security_question': user['security_question'],
                        'message': 'Password verified. Please answer security question.'
                    })
                else:
                    # Complete login
                    complete_login()
                    return jsonify({
                        'success': True,
                        'authenticated': True,
                        'user': {
                            'id': user['id'],
                            'username': user['username'],
                            'role': user['role']
                        }
                    })
        else:
            _record_failed_attempt('login')
            return jsonify({'error': 'Invalid credentials'}), 401

    elif step == 'totp':
        # Step 2: Verify TOTP code
        if 'pending_user_id' not in session or session.get('auth_step') != 'password_verified':
            return jsonify({'error': 'Invalid session state. Start from login.'}), 400

        totp_code = data.get('totp_code', '').strip()

        # Validate format: must be exactly 6 digits
        if not totp_code or not totp_code.isdigit() or len(totp_code) != 6:
            _record_failed_attempt('login')
            return jsonify({'error': 'Invalid 2FA code format. Code must be exactly 6 digits.'}), 400

        db = get_db()
        user = db.execute(
            "SELECT totp_secret, security_question FROM auth_users WHERE id = ?",
            (session.get('pending_user_id'),)
        ).fetchone()
        if not user:
            return jsonify({'error': 'Invalid session state. Start from login.'}), 400

        if verify_totp(user['totp_secret'], totp_code):
            session['auth_step'] = 'totp_verified'

            # Check if security question is needed
            if user['security_question']:
                return jsonify({
                    'success': True,
                    'next_step': 'security',
                    'security_question': user['security_question'],
                    'message': '2FA verified. Please answer security question.'
                })
            else:
                # Complete login
                complete_login()
                return jsonify({
                    'success': True,
                    'authenticated': True,
                    'user': {
                        'id': session['user_id'],
                        'username': session['username'],
                        'role': session['role']
                    }
                })
        else:
            _record_failed_attempt('login')
            return jsonify({'error': 'Invalid 2FA code'}), 401

    elif step == 'security':
        # Step 3: Verify security question
        expected_step = 'totp_verified' if session.get('pending_totp_enabled') else 'password_verified'
        if 'pending_user_id' not in session or session.get('auth_step') != expected_step:
            return jsonify({'error': 'Invalid session state. Start from login.'}), 400

        answer = data.get('security_answer', '').strip().lower()
        db = get_db()
        user = db.execute(
            "SELECT security_answer FROM auth_users WHERE id = ?",
            (session.get('pending_user_id'),)
        ).fetchone()
        if not user:
            return jsonify({'error': 'Invalid session state. Start from login.'}), 400

        expected = user['security_answer'] or ''

        if _verify_and_upgrade(db, session.get('pending_user_id'), 'security_answer', expected, answer):
            complete_login()
            return jsonify({
                'success': True,
                'authenticated': True,
                'user': {
                    'id': session['user_id'],
                    'username': session['username'],
                    'role': session['role']
                }
            })
        else:
            _record_failed_attempt('login')
            return jsonify({'error': 'Incorrect security answer'}), 401

    else:
        return jsonify({'error': f'Unknown step: {step}'}), 400


@app.route('/api/totp/current')
def api_totp_current():
    """Get current TOTP token (for testing/demo only - remove in production!)"""
    if not ENABLE_TOTP_TEST_ENDPOINT:
        return jsonify({'error': 'Not found'}), 404
    username = request.args.get('username', 'admin')
    db = get_db()
    user = db.execute("SELECT totp_secret FROM auth_users WHERE username = ?", (username,)).fetchone()

    if user and user['totp_secret']:
        return jsonify({
            'username': username,
            'totp_token': get_totp_token(user['totp_secret']),
            'valid_for_seconds': 30 - (int(time.time()) % 30)
        })
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    """API logout endpoint"""
    log_action('api_logout')
    session.clear()
    return jsonify({'success': True})


@app.route('/api/tables')
@login_required
def api_tables():
    """Get list of tables"""
    if not ENABLE_QUERY_CONSOLE:
        return jsonify({'error': 'Query console disabled'}), 403
    db = get_db()
    tables = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'auth_users'"
    ).fetchall()

    result = []
    for table in tables:
        table_name = table['name']
        count = db.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        columns = db.execute(f"PRAGMA table_info({table_name})").fetchall()
        result.append({
            'name': table_name,
            'row_count': count,
            'columns': [{'name': col['name'], 'type': col['type']} for col in columns]
        })

    return jsonify({'tables': result})


@app.route('/api/query', methods=['POST'])
@login_required
def api_query():
    """Execute a SQL query"""
    if not ENABLE_QUERY_CONSOLE:
        return jsonify({'error': 'Query console disabled'}), 403
    data = request.get_json() or {}
    query = data.get('query', '').strip()

    if not query:
        return jsonify({'error': 'No query provided'}), 400

    # Security: Only allow SELECT queries
    query_lower = query.lower()
    if not query_lower.startswith('select') and not query_lower.startswith('pragma'):
        return jsonify({'error': 'Only SELECT queries are allowed'}), 403

    # Block access to auth_users table
    if 'auth_users' in query_lower:
        return jsonify({'error': 'Access denied to this table'}), 403

    try:
        db = get_db()
        cursor = db.execute(query)
        columns = [description[0] for description in cursor.description] if cursor.description else []
        rows = cursor.fetchall()

        log_action('query', query=query)

        return jsonify({
            'success': True,
            'columns': columns,
            'data': [dict(row) for row in rows],
            'row_count': len(rows)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/table/<table_name>')
@login_required
def api_table_data(table_name):
    """Get data from a specific table"""
    if not ENABLE_QUERY_CONSOLE:
        return jsonify({'error': 'Query console disabled'}), 403
    if table_name == 'auth_users':
        return jsonify({'error': 'Access denied'}), 403

    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)

    try:
        db = get_db()

        # Get total count
        total = db.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]

        # Get data
        rows = db.execute(f"SELECT * FROM {table_name} LIMIT ? OFFSET ?", (limit, offset)).fetchall()

        log_action('view_table', table_name=table_name)

        return jsonify({
            'success': True,
            'table': table_name,
            'data': [dict(row) for row in rows],
            'total': total,
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


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


@app.route('/api/audit/verify')
@login_required
def api_audit_verify():
    """Admin-only: verify audit log integrity"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    valid, info = verify_audit_chain()
    return jsonify({'valid': valid, 'info': info})


# Initialize database on startup
with app.app_context():
    init_db()


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
