from __future__ import annotations

from typing import Any

from sqlalchemy import MetaData, Table, func, select
from sqlalchemy.orm import Session


class TableService:
    def __init__(self, session: Session):
        self.session = session

    def get_table_data(self, table_name: str, limit: int, offset: int) -> tuple[int, list[dict[str, Any]]]:
        metadata = MetaData()
        table = Table(table_name, metadata, autoload_with=self.session.bind)
        total = self.session.execute(select(func.count()).select_from(table)).scalar_one()
        rows = self.session.execute(select(table).limit(limit).offset(offset)).mappings().all()
        return int(total), [dict(row) for row in rows]

