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


def get_csrf_token(client) -> str:
    client.get("/connect")
    with client.session_transaction() as sess:
        return str(sess["csrf_token"])


def test_proxy_connect_requires_csrf(proxy_client):
    resp = proxy_client.post("/connect", data={"step": "credentials", "username": "alice", "password": "pw"})
    assert resp.status_code == 400


def test_proxy_web_connect_multistep_happy_path(proxy_client, proxy_module_demo, monkeypatch):
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
        return {"success": False, "requires_totp": True, "message": "Please enter your 2FA code"}

    monkeypatch.setattr(proxy_module_demo.module.CredentialVault, "login", fake_login)

    csrf = get_csrf_token(proxy_client)

    resp = proxy_client.post(
        "/connect",
        data={"step": "credentials", "username": "alice", "password": "pw", "csrf_token": csrf},
    )
    assert resp.status_code == 302
    assert "step=totp" in resp.headers["Location"]

    resp = proxy_client.post(
        "/connect",
        data={"step": "totp", "totp_code": "123456", "csrf_token": csrf},
    )
    assert resp.status_code == 302
    assert "step=security" in resp.headers["Location"]

    resp = proxy_client.post(
        "/connect",
        data={"step": "security", "security_answer": "blue", "csrf_token": csrf},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")

    home = proxy_client.get("/")
    assert home.status_code == 200

