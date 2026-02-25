from __future__ import annotations

from types import SimpleNamespace

from flask import Flask

from proxy_clone.api.blueprint import ProxyApiBlueprintDependencies, ProxyApiController
from proxy_clone.web.auth_guards import pending_connect_step
from proxy_clone.state.credential_vault import CredentialVault
from proxy_clone.web.routes import ProxyWebController


class DummyHttpSession:
    def __init__(self) -> None:
        self.verify: bool = False
        self.cookies: dict[str, str] = {}

    def request(self, method, url, timeout=None, **kwargs):  # pragma: no cover - defensive stub
        raise AssertionError(f"Unexpected request: {method} {url}")


class FakeResponse:
    def __init__(self, *, status_code: int, payload=None) -> None:
        self.status_code = status_code
        self.payload = payload
        self.content = b"{}"
        self.headers = {"Content-Type": "application/json"}

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class FakeVault:
    def __init__(self, *, ensure_session_result: bool = True) -> None:
        self.ensure_session_result = ensure_session_result
        self.credentials: dict[str, str] = {}
        self.auth_state: dict[str, str] = {}
        self.proxy_calls: list[tuple[str, str, dict]] = []

    def ensure_session(self) -> bool:
        return self.ensure_session_result

    def proxy_request(self, method: str, path: str, **kwargs):
        self.proxy_calls.append((method, path, kwargs))
        return None

    def get_status(self) -> dict[str, object]:
        return {
            "has_credentials": bool(self.credentials),
            "username": self.credentials.get("username"),
            "captured_at": None,
            "has_totp": False,
            "has_security_answer": False,
            "security_question": None,
            "has_session": False,
            "last_login": None,
            "active": False,
            "auth_state": self.auth_state,
        }

    def store_credentials(self, username, password) -> None:
        self.credentials = {"username": str(username), "password": str(password)}

    def login(self, totp_code=None, security_answer=None):
        return {"success": True}

    def reset_auth(self, clear_credentials: bool = False) -> None:
        if clear_credentials:
            self.credentials = {}
        self.auth_state = {}


def make_vault() -> CredentialVault:
    return CredentialVault(
        database_server_url="http://db.local",
        ssl_verify=False,
        session_factory=DummyHttpSession,
    )


def test_credential_vault_response_json_handles_invalid_payloads():
    invalid_json = FakeResponse(status_code=200, payload=ValueError("boom"))
    list_json = FakeResponse(status_code=200, payload=[1, 2, 3])
    dict_json = FakeResponse(status_code=200, payload={"ok": True})

    assert CredentialVault.response_json(invalid_json)["error"] == "Upstream returned an invalid JSON response"
    assert CredentialVault.response_json(list_json)["error"] == "Upstream returned an unexpected response payload"
    assert CredentialVault.response_json(dict_json) == {"ok": True}


def test_credential_vault_determine_login_attempt_respects_auth_state():
    vault = make_vault()

    attempt = vault.determine_login_attempt(totp_code="123456", security_answer=None)
    assert attempt.handler == "totp"
    assert attempt.value == "123456"

    vault.auth_state = {"current_step": "waiting_security"}
    security_attempt = vault.determine_login_attempt(totp_code=None, security_answer="blue")
    assert security_attempt.handler == "security"
    assert security_attempt.value == "blue"

    wrong_step_attempt = vault.determine_login_attempt(totp_code="123456", security_answer=None)
    assert wrong_step_attempt.handler == "password"


def test_credential_vault_finalize_login_step_result_resets_on_invalid_session():
    vault = make_vault()
    vault.auth_state = {"current_step": "waiting_totp"}
    response = FakeResponse(status_code=400)

    result = vault.finalize_login_step_result(
        response=response,
        data={"error": "Invalid session state. Start from login."},
        failure_message="2FA verification failed",
        incomplete_message="Authentication failed after 2FA",
        reset_password_on_invalid_session=True,
    )

    assert result["success"] is False
    assert result["error"] == "Invalid session state. Start from login."
    assert vault.auth_state["current_step"] == "password"


def test_proxy_web_controller_helpers_are_pure_and_predictable():
    assert ProxyWebController.normalize_connect_step("totp") == "totp"
    assert ProxyWebController.normalize_connect_step("bogus") == "credentials"

    assert ProxyWebController.totp_validation_error("") == "Please enter the 2FA code"
    assert ProxyWebController.totp_validation_error("12ab") == "2FA code must be exactly 6 digits"
    assert ProxyWebController.totp_validation_error("123456") is None

    rewritten = ProxyWebController.rewrite_mirrored_html('<body><a href="/x"></a><form action="/api"></form>')
    assert "PROXY MIRROR" in rewritten
    assert 'href="/mirror/x"' in rewritten
    assert 'action="/mirror/api"' in rewritten

    assert pending_connect_step({"current_step": "waiting_totp"}) == "totp"
    assert pending_connect_step({"current_step": "waiting_security"}) == "security"
    assert pending_connect_step({"current_step": "password"}) is None


def test_proxy_web_controller_mirror_api_request_params_tracks_request_method():
    app = Flask(__name__)

    with app.test_request_context("/mirror/api/test", method="GET"):
        method, kwargs = ProxyWebController.mirror_api_request_params()
        assert method == "GET"
        assert kwargs == {}

    with app.test_request_context("/mirror/api/test", method="POST", json={"query": "select 1"}):
        method, kwargs = ProxyWebController.mirror_api_request_params()
        assert method == "POST"
        assert kwargs == {"json": {"query": "select 1"}}


def test_proxy_api_controller_require_proxy_session_returns_401_when_disconnected():
    app = Flask(__name__)
    deps = ProxyApiBlueprintDependencies(
        request_validator=SimpleNamespace(parse_json=None, parse_mapping=None),
        connect_request_model=object(),
        query_request_model=object(),
        table_path_model=object(),
        api_service_factory=lambda: SimpleNamespace(health=lambda: {"status": "ok"}, status=lambda: {"ok": True}),
        feature_enabled=lambda view: view,
        proxy_status_available=lambda view: view,
        vault=FakeVault(ensure_session_result=False),
    )
    controller = ProxyApiController(deps)

    with app.app_context():
        vault, error_response = controller.require_proxy_session("Not connected")
        assert vault is None
        response, status = error_response
        assert status == 401
        assert response.get_json()["error"] == "Not connected"
