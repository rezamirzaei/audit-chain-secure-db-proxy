from __future__ import annotations

from sqlalchemy import inspect


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

