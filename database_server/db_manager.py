from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .db_config import DbConfig, load_db_config


class DatabaseSessionManager:
    def __init__(self, config: DbConfig):
        self.config = config
        connect_args = {}
        if config.backend == "sqlite":
            os.makedirs(os.path.dirname(config.sqlite_path), exist_ok=True)
            connect_args = {"check_same_thread": False}
        self.engine = create_engine(
            config.database_url,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
        self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    @classmethod
    def from_env(cls) -> DatabaseSessionManager:
        return cls(load_db_config())

    def session(self) -> Session:
        return self._session_factory()

