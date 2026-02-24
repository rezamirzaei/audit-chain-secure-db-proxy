from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from database_server.domain import build_audit_payload, hash_audit_payload, verify_audit_chain


def make_row(*, row_id: int, prev_hash: str, timestamp: datetime, query: str) -> SimpleNamespace:
    payload = build_audit_payload(
        prev_hash,
        timestamp=timestamp.isoformat(),
        user_id=1,
        action="query",
        table_name=None,
        query=query,
    )
    return SimpleNamespace(
        id=row_id,
        timestamp=timestamp,
        user_id=1,
        action="query",
        table_name=None,
        query=query,
        entry_hash=hash_audit_payload(payload),
    )


def test_verify_audit_chain_accepts_valid_chain():
    ts1 = datetime(2026, 2, 23, 0, 0, 0)
    row1 = make_row(row_id=1, prev_hash="", timestamp=ts1, query="SELECT 1")

    ts2 = datetime(2026, 2, 23, 0, 0, 1)
    row2 = make_row(row_id=2, prev_hash=row1.entry_hash, timestamp=ts2, query="SELECT 2")

    ok, info = verify_audit_chain([row1, row2])
    assert ok is True
    assert info is None


def test_verify_audit_chain_detects_tampering():
    ts1 = datetime(2026, 2, 23, 0, 0, 0)
    row1 = make_row(row_id=1, prev_hash="", timestamp=ts1, query="SELECT 1")

    ts2 = datetime(2026, 2, 23, 0, 0, 1)
    row2 = make_row(row_id=2, prev_hash=row1.entry_hash, timestamp=ts2, query="SELECT 2")

    # Tamper with data without updating the hash.
    row2.query = "SELECT 999"

    ok, info = verify_audit_chain([row1, row2])
    assert ok is False
    assert info and info["id"] == 2
