from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..persistence.models import AuditLog


def build_audit_payload(
    prev_hash: str,
    *,
    timestamp: str,
    user_id: int | None,
    action: str | None,
    table_name: str | None,
    query: str | None,
) -> str:
    return f"{prev_hash}|{timestamp}|{user_id}|{action}|{table_name or ''}|{query or ''}"


def hash_audit_payload(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditRowLike(Protocol):
    id: int
    timestamp: Any
    user_id: int | None
    action: str | None
    table_name: str | None
    query: str | None
    entry_hash: str | None


def verify_audit_chain(rows: Sequence[AuditRowLike]) -> tuple[bool, dict[str, Any] | None]:
    """Verify the audit chain hashes match row payloads in order."""
    prev_hash = ""
    for row in rows:
        timestamp = row.timestamp.isoformat() if isinstance(row.timestamp, datetime) else str(row.timestamp)
        payload = build_audit_payload(
            prev_hash,
            timestamp=timestamp,
            user_id=row.user_id,
            action=row.action,
            table_name=row.table_name,
            query=row.query,
        )
        expected = hash_audit_payload(payload)
        if row.entry_hash != expected:
            return False, {"id": row.id, "expected": expected, "actual": row.entry_hash}
        prev_hash = row.entry_hash or ""
    return True, None


class AuditService:
    def __init__(self, session: Session):
        self.session = session

    def log_action(self, *, user_id: int, action: str, table_name: str | None, query: str | None) -> None:
        prev_row = self.session.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalar_one_or_none()
        prev_hash = prev_row.entry_hash if prev_row and prev_row.entry_hash else ""
        ts = datetime.utcnow()
        payload = build_audit_payload(
            prev_hash,
            timestamp=ts.isoformat(),
            user_id=user_id,
            action=action,
            table_name=table_name,
            query=query,
        )
        entry_hash = hash_audit_payload(payload)
        self.session.add(
            AuditLog(
                user_id=user_id,
                action=action,
                table_name=table_name,
                query=query,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                timestamp=ts,
            )
        )
        self.session.commit()

    def verify_chain(self) -> tuple[bool, dict[str, Any] | None]:
        rows = self.session.execute(select(AuditLog).order_by(AuditLog.id)).scalars().all()
        return verify_audit_chain(rows)
