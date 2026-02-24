from __future__ import annotations

"""Verify tamper-evident audit log chain.

Recommended usage:
  python -m database_server.tools.verify_audit_chain
"""

import os

from sqlalchemy.orm import Session

from ..persistence import DatabaseSessionManager, load_db_config
from ..domain import AuditService


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
