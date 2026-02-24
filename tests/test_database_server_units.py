from __future__ import annotations

import pytest
from pydantic import ValidationError

from database_server.api_support import LoginSessionState
from database_server.api_schemas import LoginApiRequest
from database_server.services import build_audit_payload, hash_audit_payload


def test_build_audit_payload_preserves_delimiters_for_missing_fields():
    payload = build_audit_payload(
        "prevhash",
        timestamp="2026-02-23T00:00:00",
        user_id=7,
        action="query",
        table_name=None,
        query=None,
    )

    assert payload == "prevhash|2026-02-23T00:00:00|7|query||"


def test_hash_audit_payload_is_stable_and_sensitive_to_changes():
    payload = "a|b|c"
    same_hash = hash_audit_payload(payload)
    changed_hash = hash_audit_payload("a|b|d")

    assert same_hash == hash_audit_payload(payload)
    assert same_hash != changed_hash
    assert len(same_hash) == 64


def test_login_session_state_pending_user_id_parses_and_rejects_invalid_values():
    store: dict[str, object] = {}
    state = LoginSessionState(session_store=store)

    assert state.pending_user_id() is None

    store["pending_user_id"] = "42"
    assert state.pending_user_id() == 42

    store["pending_user_id"] = "not-an-int"
    assert state.pending_user_id() is None


def test_login_api_request_validates_totp_format():
    with pytest.raises(ValidationError):
        LoginApiRequest(step="totp", totp_code="")
    with pytest.raises(ValidationError):
        LoginApiRequest(step="totp", totp_code="12345")
    with pytest.raises(ValidationError):
        LoginApiRequest(step="totp", totp_code="12ab56")

    payload = LoginApiRequest(step="totp", totp_code="123456")
    assert payload.totp_code == "123456"
