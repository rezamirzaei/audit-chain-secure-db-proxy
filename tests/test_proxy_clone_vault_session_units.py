from __future__ import annotations

from types import SimpleNamespace

from proxy_clone.state.auth_flow import LoginOutcome
from proxy_clone.state.credential_vault import CredentialVault


class StubClient:
    def __init__(self, *, authenticated: bool) -> None:
        self.authenticated = authenticated
        self.calls: list[tuple[str, str, int]] = []
        self.session = SimpleNamespace(cookies={})

    def new_session(self) -> None:  # pragma: no cover - required by CredentialVault.new_session
        return None

    def get_json(self, path: str, *, timeout: int):
        self.calls.append(("GET", path, timeout))
        return SimpleNamespace(status_code=200), {"authenticated": self.authenticated}


def test_credential_vault_ensure_session_returns_false_without_credentials():
    client = StubClient(authenticated=True)
    vault = CredentialVault(database_server_url="http://db.local", ssl_verify=False, client=client)

    assert vault.ensure_session() is False
    assert client.calls == []


def test_credential_vault_ensure_session_returns_true_when_upstream_session_is_active():
    client = StubClient(authenticated=True)
    vault = CredentialVault(database_server_url="http://db.local", ssl_verify=False, client=client)
    vault.credentials = {"username": "alice", "password": "pw"}

    assert vault.ensure_session() is True
    assert client.calls[0][1] == "/api/session"


def test_credential_vault_apply_login_outcome_resets_auth_state_when_requested():
    vault = CredentialVault(database_server_url="http://db.local", ssl_verify=False, client=StubClient(authenticated=False))
    vault.auth_state = {"current_step": "waiting_totp"}

    result = vault.apply_login_outcome(
        LoginOutcome(kind="error", error="Invalid session state. Start from login.", reset_to_password=True),
        failure_message="fail",
        incomplete_message="incomplete",
    )

    assert result["success"] is False
    assert vault.auth_state["current_step"] == "password"

