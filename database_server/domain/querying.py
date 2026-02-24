from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


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

