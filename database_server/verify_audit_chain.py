#!/usr/bin/env python3
"""Verify tamper-evident audit log chain."""

import hashlib
import importlib
import os

from sqlalchemy import select


_db_module = importlib.import_module(f"{__package__}.db" if __package__ else "db")
DatabaseSessionManager = _db_module.DatabaseSessionManager
load_db_config = _db_module.load_db_config
_models_module = importlib.import_module(f"{__package__}.models" if __package__ else "models")
AuditLog = _models_module.AuditLog


def build_audit_payload(prev_hash: str, row: AuditLog) -> str:
    timestamp = row.timestamp.isoformat() if row.timestamp is not None else ""
    return (
        f"{prev_hash}|{timestamp}|{row.user_id}|{row.action}|"
        f"{row.table_name or ''}|{row.query or ''}"
    )


def main() -> None:
    cfg = load_db_config()
    if cfg.backend == "sqlite" and not os.path.exists(cfg.sqlite_path):
        print("Database not found:", cfg.sqlite_path)
        return

    manager = DatabaseSessionManager.from_env()
    with manager.session() as session:
        rows = session.execute(select(AuditLog).order_by(AuditLog.id)).scalars().all()
        prev_hash = ""
        for row in rows:
            payload = build_audit_payload(prev_hash, row)
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if row.entry_hash != expected:
                print("Audit chain verification FAILED at id", row.id)
                print(" expected:", expected)
                print(" actual:  ", row.entry_hash)
                return
            prev_hash = row.entry_hash or ""
        print("Audit chain verification OK. Entries:", len(rows))


if __name__ == "__main__":
    main()
