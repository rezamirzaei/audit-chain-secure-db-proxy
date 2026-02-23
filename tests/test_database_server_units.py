from __future__ import annotations

from flask import Flask, session

from database_server.services import build_audit_payload, hash_audit_payload
from database_server.web_routes import DatabaseWebRoutes


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


def test_database_web_routes_pending_user_id_parses_and_rejects_invalid_values():
    app = Flask(__name__)
    app.secret_key = "test-secret"

    with app.test_request_context("/"):
        assert DatabaseWebRoutes.pending_user_id() is None

        session["pending_user_id"] = "42"
        assert DatabaseWebRoutes.pending_user_id() == 42

        session["pending_user_id"] = "not-an-int"
        assert DatabaseWebRoutes.pending_user_id() is None


def test_database_web_routes_validates_totp_format():
    assert DatabaseWebRoutes.is_valid_totp_code("") is False
    assert DatabaseWebRoutes.is_valid_totp_code("12345") is False
    assert DatabaseWebRoutes.is_valid_totp_code("12ab56") is False
    assert DatabaseWebRoutes.is_valid_totp_code("123456") is True
