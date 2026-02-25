from __future__ import annotations

from types import SimpleNamespace

from proxy_clone.state.auth_flow import (
    LoginReply,
    determine_login_attempt,
    interpret_login_reply,
)
from proxy_clone.state.upstream_client import UpstreamClient


def test_determine_login_attempt_prefers_totp_unless_waiting_for_security():
    attempt = determine_login_attempt({}, totp_code="123456", security_answer=None)
    assert attempt.handler == "totp"
    assert attempt.value == "123456"

    attempt2 = determine_login_attempt({"current_step": "waiting_security"}, totp_code="123456", security_answer=None)
    assert attempt2.handler == "password"


def test_interpret_login_reply_handles_invalid_session_reset():
    outcome = interpret_login_reply(
        LoginReply(status_code=400, data={"error": "Invalid session state. Start from login."}),
        failure_message="fail",
        incomplete_message="incomplete",
        reset_password_on_invalid_session=True,
    )
    assert outcome.kind == "error"
    assert outcome.reset_to_password is True


def test_interpret_login_reply_routes_next_step_and_authenticated():
    totp = interpret_login_reply(
        LoginReply(status_code=200, data={"next_step": "totp"}),
        failure_message="fail",
        incomplete_message="incomplete",
    )
    assert totp.kind == "require_totp"

    security = interpret_login_reply(
        LoginReply(status_code=200, data={"next_step": "security", "security_question": "Favorite color?"}),
        failure_message="fail",
        incomplete_message="incomplete",
    )
    assert security.kind == "require_security"
    assert security.security_question == "Favorite color?"

    authed = interpret_login_reply(
        LoginReply(status_code=200, data={"authenticated": True, "user": {"username": "alice"}}),
        failure_message="fail",
        incomplete_message="incomplete",
    )
    assert authed.kind == "authenticated"
    assert authed.authenticated_data == {"authenticated": True, "user": {"username": "alice"}}


def test_interpret_login_reply_includes_state_when_requested():
    outcome = interpret_login_reply(
        LoginReply(status_code=200, data={"foo": "bar"}),
        failure_message="fail",
        incomplete_message="incomplete",
        include_state_on_incomplete=True,
    )
    assert outcome.kind == "incomplete"
    assert outcome.state == {"foo": "bar"}


def test_upstream_client_builds_urls_and_parses_json():
    class DummySession:
        def __init__(self) -> None:
            self.verify = False
            self.cookies: dict[str, str] = {}
            self.calls: list[tuple[str, str, int, dict]] = []

        def request(self, method: str, url: str, timeout: int, **kwargs):
            self.calls.append((method, url, timeout, kwargs))
            return SimpleNamespace(status_code=200, json=lambda: {"ok": True})

    client = UpstreamClient(base_url="http://example", ssl_verify=True, session_factory=DummySession)
    assert client.url("/x") == "http://example/x"

    resp, data = client.post_json("/api/login", {"step": "password"}, timeout=1)
    assert resp.status_code == 200
    assert data == {"ok": True}
    assert client.session.verify is True
    assert client.session.calls[0][0] == "POST"
    assert client.session.calls[0][1] == "http://example/api/login"
