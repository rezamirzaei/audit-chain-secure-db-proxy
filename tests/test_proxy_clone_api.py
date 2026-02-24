import pytest

from tests.support import create_fresh_app


@pytest.fixture()
def proxy_module_demo(monkeypatch):
    monkeypatch.setenv("APP_ENV", "demo")
    monkeypatch.setenv("PROXY_FEATURES_ENABLED", "true")
    monkeypatch.delenv("REDIS_URL", raising=False)

    fresh = create_fresh_app("proxy_clone")
    fresh.app.testing = True
    yield fresh
    fresh.app.extensions["vault_registry"].vaults.clear()


@pytest.fixture()
def proxy_client(proxy_module_demo):
    with proxy_module_demo.app.test_client() as client:
        yield client


@pytest.fixture()
def proxy_client_features_disabled(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("PROXY_FEATURES_ENABLED", "false")
    monkeypatch.delenv("REDIS_URL", raising=False)

    fresh = create_fresh_app("proxy_clone")
    fresh.app.testing = True
    with fresh.app.test_client() as client:
        yield client
    fresh.app.extensions["vault_registry"].vaults.clear()


def test_proxy_status_disabled_when_feature_off(proxy_client_features_disabled):
    health_resp = proxy_client_features_disabled.get("/api/health")
    assert health_resp.status_code == 404
    resp = proxy_client_features_disabled.get("/api/status")
    assert resp.status_code == 404


def test_proxy_status_requires_local_proxy_session(proxy_client):
    health_resp = proxy_client.get("/api/health")
    assert health_resp.status_code == 200
    assert health_resp.get_json()["status"] == "ok"

    resp = proxy_client.get("/api/status")
    assert resp.status_code == 401
    assert "connected" in resp.get_json()["error"].lower()


def test_proxy_api_rejects_invalid_json_payloads(proxy_client):
    resp = proxy_client.post("/api/connect", json={"step": "password", "username": "alice", "password": 123})
    assert resp.status_code == 400
    payload = resp.get_json()
    assert payload["error"] == "Invalid request payload"
    assert payload["details"]

    extra_field_resp = proxy_client.post(
        "/api/connect",
        json={"step": "password", "username": "alice", "password": "pw", "unexpected": True},
    )
    assert extra_field_resp.status_code == 400
    assert extra_field_resp.get_json()["error"] == "Invalid request payload"


def test_proxy_table_endpoint_validates_table_name(proxy_client, proxy_module_demo, monkeypatch):
    monkeypatch.setattr(proxy_module_demo.module.CredentialVault, "ensure_session", lambda self: True)

    resp = proxy_client.get("/api/table/not-valid-name")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Invalid request payload"


def test_proxy_status_shape_is_sanitized_after_connect(proxy_client, proxy_module_demo, monkeypatch):
    def fake_login(self, totp_code=None, security_answer=None):
        self.auth_state = {"current_step": "waiting_totp"}
        return {"success": False, "requires_totp": True}

    monkeypatch.setattr(proxy_module_demo.module.CredentialVault, "login", fake_login)
    connect_resp = proxy_client.post("/api/connect", json={"step": "password", "username": "alice", "password": "pw"})
    assert connect_resp.status_code == 200

    resp = proxy_client.get("/api/status")
    assert resp.status_code == 200
    payload = resp.get_json()
    for key in ["has_credentials", "has_session", "has_totp", "has_security_answer", "active"]:
        assert key in payload
    for key in ["username", "security_question", "auth_state", "captured_at", "last_login"]:
        assert key not in payload


def test_proxy_api_connect_multistep_and_session_isolation(proxy_module_demo, monkeypatch):
    def fake_login(self, totp_code=None, security_answer=None):
        if security_answer:
            self.store_security_answer(self.auth_state.get("security_question", "Favorite color?"), security_answer)
            self.active_session = True
            self.auth_state = {"authenticated": True, "user": {"username": self.credentials.get("username")}}
            return {"success": True, "data": {"authenticated": True}}

        if totp_code:
            self.store_totp_code(totp_code)
            self.auth_state["current_step"] = "waiting_security"
            self.auth_state["security_question"] = "Favorite color?"
            return {
                "success": False,
                "requires_security": True,
                "security_question": "Favorite color?",
                "message": "Please answer your security question",
            }

        self.auth_state = {"current_step": "waiting_totp"}
        return {
            "success": False,
            "requires_totp": True,
            "message": "Please enter your 2FA code",
        }

    monkeypatch.setattr(proxy_module_demo.module.CredentialVault, "login", fake_login)

    client_a = proxy_module_demo.app.test_client()
    client_b = proxy_module_demo.app.test_client()

    resp_a = client_a.post("/api/connect", json={"step": "password", "username": "alice", "password": "pw-a"})
    assert resp_a.status_code == 200
    json_a = resp_a.get_json()
    assert json_a["requires_totp"] is True
    assert json_a["status"]["has_credentials"] is True

    resp_b = client_b.post("/api/connect", json={"step": "password", "username": "bob", "password": "pw-b"})
    assert resp_b.status_code == 200
    json_b = resp_b.get_json()
    assert json_b["requires_totp"] is True
    assert json_b["status"]["has_credentials"] is True

    with client_a.session_transaction() as sess_a:
        vault_a_id = sess_a["vault_id"]
    with client_b.session_transaction() as sess_b:
        vault_b_id = sess_b["vault_id"]

    assert vault_a_id != vault_b_id
    vaults = proxy_module_demo.app.extensions["vault_registry"].vaults
    assert vaults[vault_a_id].credentials["username"] == "alice"
    assert vaults[vault_b_id].credentials["username"] == "bob"

    resp_totp = client_a.post("/api/connect", json={"step": "totp", "totp_code": "123456"})
    assert resp_totp.status_code == 200
    json_totp = resp_totp.get_json()
    assert json_totp["requires_security"] is True
    assert json_totp["status"]["has_totp"] is True

    resp_sec = client_a.post("/api/connect", json={"step": "security", "security_answer": "blue"})
    assert resp_sec.status_code == 200
    json_sec = resp_sec.get_json()
    assert json_sec["success"] is True
    assert json_sec["status"]["has_security_answer"] is True

    status_a = client_a.get("/api/status").get_json()
    status_b = client_b.get("/api/status").get_json()
    assert status_a["has_credentials"] is True
    assert status_a["has_session"] is False  # fake_login does not store upstream cookies
    assert status_b["has_security_answer"] is False
