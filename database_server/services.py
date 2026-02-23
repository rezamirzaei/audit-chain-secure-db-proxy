from __future__ import annotations

from datetime import datetime
import hashlib
from typing import Any

from sqlalchemy import MetaData, Table, func, inspect, select, text
from sqlalchemy.orm import Session

from .models import AuditLog, AuthUser


class UserService:
    def __init__(self, session: Session):
        self.session = session

    def get_by_username(self, username: str) -> AuthUser | None:
        return self.session.execute(select(AuthUser).where(AuthUser.username == username)).scalar_one_or_none()

    def get_by_id(self, user_id: int) -> AuthUser | None:
        return self.session.execute(select(AuthUser).where(AuthUser.id == user_id)).scalar_one_or_none()


class AuditService:
    def __init__(self, session: Session):
        self.session = session

    def log_action(self, *, user_id: int, action: str, table_name: str | None, query: str | None) -> None:
        prev_row = self.session.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalar_one_or_none()
        prev_hash = prev_row.entry_hash if prev_row and prev_row.entry_hash else ""
        ts = datetime.utcnow()
        payload = f"{prev_hash}|{ts.isoformat()}|{user_id}|{action}|{table_name or ''}|{query or ''}"
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
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
        prev_hash = ""
        for row in rows:
            timestamp = row.timestamp.isoformat() if isinstance(row.timestamp, datetime) else str(row.timestamp)
            payload = f"{prev_hash}|{timestamp}|{row.user_id}|{row.action}|{row.table_name or ''}|{row.query or ''}"
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if row.entry_hash != expected:
                return False, {"id": row.id, "expected": expected, "actual": row.entry_hash}
            prev_hash = row.entry_hash or ""
        return True, None


class SchemaService:
    def __init__(self, engine):
        self.engine = engine

    def list_tables(self) -> list[str]:
        inspector = inspect(self.engine)
        names = inspector.get_table_names()
        return [name for name in names if not name.startswith("sqlite_")]

    def table_columns(self, table_name: str) -> list[dict[str, str]]:
        inspector = inspect(self.engine)
        columns = inspector.get_columns(table_name)
        return [{"name": col["name"], "type": str(col["type"])} for col in columns]


class QueryService:
    def __init__(self, session: Session):
        self.session = session

    def backend(self) -> str:
        return self.session.bind.dialect.name

    def execute_readonly(self, query: str) -> tuple[list[str], list[dict[str, Any]]]:
        result = self.session.execute(text(query))
        rows = result.mappings().all()
        columns = list(result.keys())
        return columns, [dict(row) for row in rows]


class TableService:
    def __init__(self, session: Session):
        self.session = session

    def get_table_data(self, table_name: str, limit: int, offset: int) -> tuple[int, list[dict[str, Any]]]:
        metadata = MetaData()
        table = Table(table_name, metadata, autoload_with=self.session.bind)
        total = self.session.execute(select(func.count()).select_from(table)).scalar_one()
        rows = self.session.execute(select(table).limit(limit).offset(offset)).mappings().all()
        return int(total), [dict(row) for row in rows]
