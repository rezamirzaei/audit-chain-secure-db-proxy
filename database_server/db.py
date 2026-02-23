import logging
import os
import sqlite3
import time
import importlib
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

try:
    import psycopg2
    import psycopg2.extras
except Exception:  # pragma: no cover - optional dependency for SQLite-only mode
    psycopg2 = None


logger = logging.getLogger("database_server.db")


def sqlite_db_path() -> str:
    override = (os.environ.get("SQLITE_DB_PATH") or os.environ.get("SQLITE_PATH") or "").strip()
    if override:
        return override
    if os.path.exists('/app'):
        return '/app/data/database.db'
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'database.db')


@dataclass(frozen=True)
class DbConfig:
    backend: str  # "sqlite" | "postgres"
    sqlite_path: str
    postgres_dsn: Optional[str]


def load_db_config() -> DbConfig:
    backend = (os.environ.get("DB_BACKEND") or "").strip().lower()
    dsn = (os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_DSN") or "").strip() or None

    if backend in {"postgres", "postgresql"}:
        return DbConfig(backend="postgres", sqlite_path=sqlite_db_path(), postgres_dsn=dsn)
    if backend == "sqlite":
        return DbConfig(backend="sqlite", sqlite_path=sqlite_db_path(), postgres_dsn=None)

    if dsn:
        return DbConfig(backend="postgres", sqlite_path=sqlite_db_path(), postgres_dsn=dsn)
    return DbConfig(backend="sqlite", sqlite_path=sqlite_db_path(), postgres_dsn=None)


def _qmark_to_psycopg(sql: str) -> str:
    # This codebase uses SQLite-style `?` placeholders. psycopg2 uses `%s`.
    # Queries here do not embed `?` in string literals, so a straight replacement is sufficient.
    return sql.replace("?", "%s")


class Db:
    def __init__(self, backend: str, conn: Any):
        self.backend = backend
        self._conn = conn

    def cursor(self):
        if self.backend == "postgres":
            return self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        return self._conn.cursor()

    def execute(self, sql: str, params: Optional[Sequence[Any]] = None):
        if params is None:
            params = ()
        if self.backend == "postgres":
            cur = self.cursor()
            cur.execute(_qmark_to_psycopg(sql), params)
            return cur
        return self._conn.execute(sql, params)

    def executemany(self, sql: str, seq_of_params: Iterable[Sequence[Any]]):
        if self.backend == "postgres":
            cur = self.cursor()
            cur.executemany(_qmark_to_psycopg(sql), list(seq_of_params))
            return cur
        return self._conn.executemany(sql, list(seq_of_params))

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


def connect_db(retries: int = 30, delay_seconds: float = 1.0) -> Db:
    cfg = load_db_config()

    if cfg.backend == "sqlite":
        os.makedirs(os.path.dirname(cfg.sqlite_path), exist_ok=True)
        conn = sqlite3.connect(cfg.sqlite_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return Db(backend="sqlite", conn=conn)

    if psycopg2 is None:
        raise RuntimeError("PostgreSQL backend requested but psycopg2 is not installed")
    if not cfg.postgres_dsn:
        raise RuntimeError("PostgreSQL backend requested but DATABASE_URL/POSTGRES_DSN is not set")

    last_err: Optional[Exception] = None
    for attempt in range(1, max(retries, 1) + 1):
        try:
            conn = psycopg2.connect(cfg.postgres_dsn, connect_timeout=5)
            return Db(backend="postgres", conn=conn)
        except Exception as exc:
            last_err = exc
            if attempt >= retries:
                break
            logger.warning("Postgres not ready (attempt %s/%s): %s", attempt, retries, exc)
            time.sleep(delay_seconds)

    raise RuntimeError(f"Could not connect to Postgres after {retries} attempts: {last_err}")


def init_db(db: Db, demo_mode: bool, enable_totp_test_endpoint: bool, log_info) -> None:
    """
    Initialize schema + default data.

    `log_info` is a function used by the caller for consistent logging (e.g. Flask app logger).
    """
    if db.backend == "postgres":
        _init_postgres(db, demo_mode=demo_mode, enable_totp_test_endpoint=enable_totp_test_endpoint, log_info=log_info)
    else:
        _init_sqlite(db, demo_mode=demo_mode, enable_totp_test_endpoint=enable_totp_test_endpoint, log_info=log_info)


def _init_postgres(db: Db, demo_mode: bool, enable_totp_test_endpoint: bool, log_info) -> None:
    # Tables
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            totp_secret TEXT,
            totp_enabled BOOLEAN DEFAULT TRUE,
            security_question TEXT,
            security_answer TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS employees (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            department TEXT,
            salary REAL,
            hire_date DATE,
            is_active BOOLEAN DEFAULT TRUE
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS departments (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            budget REAL,
            manager_id INTEGER,
            FOREIGN KEY (manager_id) REFERENCES employees(id)
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS projects (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            department_id INTEGER,
            start_date DATE,
            end_date DATE,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (department_id) REFERENCES departments(id)
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            action TEXT,
            table_name TEXT,
            query TEXT,
            prev_hash TEXT,
            entry_hash TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Ensure required columns exist (for existing DBs)
    required_auth_cols = {
        "role": "TEXT DEFAULT 'user'",
        "totp_secret": "TEXT",
        "totp_enabled": "BOOLEAN DEFAULT TRUE",
        "security_question": "TEXT",
        "security_answer": "TEXT",
        "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    }
    for col, definition in required_auth_cols.items():
        db.execute(f"ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS {col} {definition}")

    db.execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT")
    db.execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT")

    _backfill_audit_hashes(db)
    _ensure_default_users(db, demo_mode=demo_mode, enable_totp_test_endpoint=enable_totp_test_endpoint, log_info=log_info)
    _ensure_sample_data(db)
    db.commit()


def _init_sqlite(db: Db, demo_mode: bool, enable_totp_test_endpoint: bool, log_info) -> None:
    # Create users table for authentication with 2FA support
    db.execute(
        """
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
        """
    )

    # Ensure auth_users has all required columns (for existing DBs)
    cursor = db.execute("PRAGMA table_info(auth_users)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    required_cols = {
        "role": "TEXT DEFAULT 'user'",
        "totp_secret": "TEXT",
        "totp_enabled": "BOOLEAN DEFAULT 1",
        "security_question": "TEXT",
        "security_answer": "TEXT",
        "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    }
    for col, definition in required_cols.items():
        if col not in existing_cols:
            db.execute(f"ALTER TABLE auth_users ADD COLUMN {col} {definition}")

    # Create sample data tables
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            department TEXT,
            salary REAL,
            hire_date DATE,
            is_active BOOLEAN DEFAULT 1
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            budget REAL,
            manager_id INTEGER,
            FOREIGN KEY (manager_id) REFERENCES employees(id)
        )
        """
    )

    db.execute(
        """
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
        """
    )

    db.execute(
        """
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
        """
    )

    # Ensure audit_log has tamper-evident hash columns
    cursor = db.execute("PRAGMA table_info(audit_log)")
    audit_cols = {row[1] for row in cursor.fetchall()}
    if "prev_hash" not in audit_cols:
        db.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
    if "entry_hash" not in audit_cols:
        db.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")

    _backfill_audit_hashes(db)
    _ensure_default_users(db, demo_mode=demo_mode, enable_totp_test_endpoint=enable_totp_test_endpoint, log_info=log_info)
    _ensure_sample_data(db)
    db.commit()


def _backfill_audit_hashes(db: Db) -> None:
    import hashlib

    rows = db.execute(
        "SELECT id, user_id, action, table_name, query, timestamp, entry_hash FROM audit_log ORDER BY id"
    ).fetchall()
    if not rows:
        return
    if all(row["entry_hash"] is not None for row in rows):
        return

    prev_hash = ""
    for row in rows:
        payload = (
            f"{prev_hash}|{row['timestamp']}|{row['user_id']}|{row['action']}|"
            f"{row['table_name'] or ''}|{row['query'] or ''}"
        )
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        db.execute(
            "UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?",
            (prev_hash, entry_hash, row["id"]),
        )
        prev_hash = entry_hash


def _ensure_default_users(db: Db, demo_mode: bool, enable_totp_test_endpoint: bool, log_info) -> None:
    auth_utils = importlib.import_module(f"{__package__}.auth_utils" if __package__ else "auth_utils")
    generate_totp_secret = auth_utils.generate_totp_secret
    get_totp_token = auth_utils.get_totp_token
    _hash_value = auth_utils._hash_value
    _is_hash = auth_utils._is_hash

    # Insert default admin user if not exists (with 2FA)
    if db.execute("SELECT COUNT(*) FROM auth_users WHERE username = 'admin'").fetchone()[0] == 0:
        admin_secret = generate_totp_secret()
        analyst_secret = generate_totp_secret()
        admin_password = _hash_value("SecurePass123!")
        analyst_password = _hash_value("AnalystPass456!")
        admin_answer = _hash_value("blue")
        analyst_answer = _hash_value("fluffy")

        db.execute(
            """
            INSERT INTO auth_users (username, password, role, totp_secret, totp_enabled, security_question, security_answer)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("admin", admin_password, "admin", admin_secret, True, "What is your favorite color?", admin_answer),
        )
        db.execute(
            """
            INSERT INTO auth_users (username, password, role, totp_secret, totp_enabled, security_question, security_answer)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("analyst", analyst_password, "analyst", analyst_secret, True, "What is your pet name?", analyst_answer),
        )

        if demo_mode or enable_totp_test_endpoint:
            log_info("=== 2FA SETUP ===")
            log_info("Admin TOTP Secret: %s", admin_secret)
            log_info("Admin Current Token: %s", get_totp_token(admin_secret))
            log_info("Analyst TOTP Secret: %s", analyst_secret)
            log_info("Analyst Current Token: %s", get_totp_token(analyst_secret))
            log_info("==================")
        return

    # Existing DB: ensure user fields are present and hashed where needed
    db.execute("UPDATE auth_users SET totp_enabled = ? WHERE totp_enabled IS NULL", (True,))

    # Populate missing TOTP secrets
    missing_totp = db.execute("SELECT id, username FROM auth_users WHERE totp_secret IS NULL OR totp_secret = ''").fetchall()
    for row in missing_totp:
        secret = generate_totp_secret()
        db.execute("UPDATE auth_users SET totp_secret = ? WHERE id = ?", (secret, row["id"]))
        if demo_mode:
            log_info("[MIGRATION] Generated TOTP secret for %s: %s", row["username"], secret)

    # Populate missing security questions/answers for default users
    users = db.execute("SELECT id, username, password, security_question, security_answer FROM auth_users").fetchall()
    for row in users:
        user_id = row["id"]
        username = row["username"]
        password = row["password"]
        question = row["security_question"]
        answer = row["security_answer"]

        # Hash plaintext passwords
        if password and not _is_hash(password):
            db.execute("UPDATE auth_users SET password = ? WHERE id = ?", (_hash_value(password), user_id))

        # Ensure default security questions/answers are set and hashed
        if username == "admin" and (not question or not answer):
            db.execute(
                "UPDATE auth_users SET security_question = ?, security_answer = ? WHERE id = ?",
                ("What is your favorite color?", _hash_value("blue"), user_id),
            )
        elif username == "analyst" and (not question or not answer):
            db.execute(
                "UPDATE auth_users SET security_question = ?, security_answer = ? WHERE id = ?",
                ("What is your pet name?", _hash_value("fluffy"), user_id),
            )
        elif answer and not _is_hash(answer):
            db.execute("UPDATE auth_users SET security_answer = ? WHERE id = ?", (_hash_value(answer.lower()), user_id))


def _ensure_sample_data(db: Db) -> None:
    # Insert sample data if not exists
    if db.execute("SELECT COUNT(*) FROM departments").fetchone()[0] != 0:
        return

    departments = [
        ("Engineering", 500000, None),
        ("Marketing", 200000, None),
        ("Sales", 300000, None),
        ("Human Resources", 150000, None),
        ("Finance", 250000, None),
    ]
    db.executemany("INSERT INTO departments (name, budget, manager_id) VALUES (?, ?, ?)", departments)

    employees = [
        ("John Smith", "john.smith@company.com", "Engineering", 95000, "2020-01-15", True),
        ("Sarah Johnson", "sarah.j@company.com", "Engineering", 105000, "2019-06-01", True),
        ("Mike Wilson", "mike.w@company.com", "Marketing", 75000, "2021-03-20", True),
        ("Emily Davis", "emily.d@company.com", "Sales", 85000, "2020-08-10", True),
        ("Robert Brown", "robert.b@company.com", "Finance", 90000, "2018-11-05", True),
        ("Lisa Anderson", "lisa.a@company.com", "Human Resources", 70000, "2021-01-10", True),
        ("David Martinez", "david.m@company.com", "Engineering", 115000, "2017-04-22", True),
        ("Jennifer Taylor", "jennifer.t@company.com", "Marketing", 80000, "2020-09-15", True),
        ("James Thomas", "james.t@company.com", "Sales", 95000, "2019-02-28", True),
        ("Amanda White", "amanda.w@company.com", "Finance", 100000, "2018-07-01", True),
    ]
    db.executemany(
        "INSERT INTO employees (name, email, department, salary, hire_date, is_active) VALUES (?, ?, ?, ?, ?, ?)",
        employees,
    )

    projects = [
        ("Website Redesign", "Complete overhaul of company website", 1, "2024-01-01", "2024-06-30", "active"),
        ("Mobile App", "Develop iOS and Android apps", 1, "2024-03-01", "2024-12-31", "active"),
        ("Q1 Campaign", "Spring marketing campaign", 2, "2024-01-15", "2024-03-31", "completed"),
        ("Sales Expansion", "Expand to new markets", 3, "2024-02-01", "2024-08-31", "active"),
        ("HR System", "New HR management system", 4, "2024-04-01", "2024-10-31", "planning"),
    ]
    db.executemany(
        "INSERT INTO projects (name, description, department_id, start_date, end_date, status) VALUES (?, ?, ?, ?, ?, ?)",
        projects,
    )


def list_tables(db: Db) -> list[str]:
    if db.backend == "postgres":
        rows = db.execute(
            """
            SELECT table_name AS name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_type = 'BASE TABLE'
              AND table_name != 'auth_users'
            ORDER BY table_name
            """
        ).fetchall()
        return [row["name"] for row in rows]

    rows = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'auth_users'"
    ).fetchall()
    return [row["name"] for row in rows]


def table_columns(db: Db, table_name: str) -> list[dict[str, str]]:
    if db.backend == "postgres":
        rows = db.execute(
            """
            SELECT column_name AS name, data_type AS type
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = ?
            ORDER BY ordinal_position
            """,
            (table_name,),
        ).fetchall()
        return [{"name": row["name"], "type": row["type"]} for row in rows]

    cols = db.execute(f"PRAGMA table_info({table_name})").fetchall()
    return [{"name": col["name"], "type": col["type"]} for col in cols]
