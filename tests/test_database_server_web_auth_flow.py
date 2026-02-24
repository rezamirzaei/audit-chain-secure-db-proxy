import pytest

from tests.support import create_fresh_app


@pytest.fixture()
def web_client(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_ENV", "demo")
    monkeypatch.setenv("ENABLE_TOTP_TEST_ENDPOINT", "true")
    monkeypatch.setenv("ENABLE_QUERY_CONSOLE", "true")
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("SQLITE_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("DB_CONNECT_RETRIES", "1")

    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_DSN", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)

    fresh = create_fresh_app("database_server")
    fresh.app.testing = True
    with fresh.app.test_client() as client:
        yield client


def get_csrf_token(client) -> str:
    client.get("/login")
    with client.session_transaction() as sess:
        return str(sess["csrf_token"])


def test_login_requires_csrf_token(web_client):
    resp = web_client.post("/login", data={"username": "admin", "password": "SecurePass123!"})
    assert resp.status_code == 400


def test_web_login_flow_happy_path(web_client):
    csrf = get_csrf_token(web_client)
    totp = web_client.get("/api/totp/current?username=admin").get_json()["totp_token"]

    resp = web_client.post(
        "/login",
        data={"username": "admin", "password": "SecurePass123!", "csrf_token": csrf},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/verify-2fa")

    resp = web_client.post(
        "/verify-2fa",
        data={"totp_code": totp, "csrf_token": csrf},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/verify-security")

    resp = web_client.post(
        "/verify-security",
        data={"security_answer": "blue", "csrf_token": csrf},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")

    session_info = web_client.get("/api/session").get_json()
    assert session_info["authenticated"] is True
    assert session_info["username"] == "admin"

    dashboard = web_client.get("/dashboard")
    assert dashboard.status_code == 200

