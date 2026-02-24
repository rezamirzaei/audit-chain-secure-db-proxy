#!/usr/bin/env python3
"""Verify tamper-evident audit log chain."""

from __future__ import annotations

import os
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy.orm import Session

from database_server.db import DatabaseSessionManager, load_db_config
from database_server.services import AuditService


def verify_chain(session: Session) -> tuple[bool, dict[str, object] | None]:
    return AuditService(session).verify_chain()


def main() -> None:
    cfg = load_db_config()
    if cfg.backend == "sqlite" and not os.path.exists(cfg.sqlite_path):
        print("Database not found:", cfg.sqlite_path)
        return

    manager = DatabaseSessionManager.from_env()
    with manager.session() as session:
        ok, info = verify_chain(session)
        if not ok:
            info = info or {}
            print("Audit chain verification FAILED at id", info.get("id"))
            print(" expected:", info.get("expected"))
            print(" actual:  ", info.get("actual"))
            return
        print("Audit chain verification OK.")


if __name__ == "__main__":
    main()
