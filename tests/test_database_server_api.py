import importlib.util
import sys
from pathlib import Path

import pytest


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def db_client(tmp_path, monkeypatch):
    root_dir = Path(__file__).resolve().parents[1]
    db_dir = root_dir / "database_server"

    monkeypatch.setenv("APP_ENV", "demo")
    monkeypatch.setenv("ENABLE_TOTP_TEST_ENDPOINT", "true")
    monkeypatch.setenv("ENABLE_QUERY_CONSOLE", "true")
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("SQLITE_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("DB_CONNECT_RETRIES", "1")

    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_DSN", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)

    sys.path.insert(0, str(db_dir))
    module = _load_module("database_server_app", db_dir / "app.py")

    module.app.testing = True
    with module.app.test_client() as client:
        yield client


def _login_admin(client) -> None:
    totp = client.get("/api/totp/current?username=admin").get_json()["totp_token"]

    resp = client.post(
        "/api/login",
        json={"step": "password", "username": "admin", "password": "SecurePass123!"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["requires_2fa"] is True

    resp = client.post("/api/login", json={"step": "totp", "totp_code": totp})
    assert resp.status_code == 200
    assert resp.get_json()["next_step"] == "security"

    resp = client.post("/api/login", json={"step": "security", "security_answer": "blue"})
    assert resp.status_code == 200
    assert resp.get_json()["authenticated"] is True


def test_health(db_client):
    resp = db_client.get("/api/health")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["status"] == "healthy"


def test_database_api_rejects_invalid_json_payloads(db_client):
    login_resp = db_client.post("/api/login", json={"step": "password", "username": "admin", "password": 123})
    assert login_resp.status_code == 400
    login_json = login_resp.get_json()
    assert login_json["error"] == "Invalid request payload"
    assert login_json["details"]

    _login_admin(db_client)
    query_resp = db_client.post("/api/query", json={"query": "   "})
    assert query_resp.status_code == 400
    query_json = query_resp.get_json()
    assert query_json["error"] == "Invalid request payload"
    assert query_json["details"]


def test_login_flow_query_and_audit(db_client):
    _login_admin(db_client)

    tables_resp = db_client.get("/api/tables")
    assert tables_resp.status_code == 200
    tables = {t["name"] for t in tables_resp.get_json()["tables"]}
    assert {"employees", "departments", "projects", "audit_log"} <= tables

    query_resp = db_client.post("/api/query", json={"query": "SELECT COUNT(*) AS cnt FROM departments"})
    assert query_resp.status_code == 200
    query_json = query_resp.get_json()
    assert query_json["success"] is True
    assert query_json["row_count"] == 1
    assert "cnt" in query_json["columns"]

    denied = db_client.post("/api/query", json={"query": "SELECT * FROM auth_users"})
    assert denied.status_code == 403
    assert "denied" in denied.get_json()["error"].lower()

    audit_resp = db_client.get("/api/audit/verify")
    assert audit_resp.status_code == 200
    assert audit_resp.get_json()["valid"] is True
