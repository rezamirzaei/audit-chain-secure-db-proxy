from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping


@dataclass(frozen=True)
class DbConfig:
    backend: Literal["sqlite", "postgres"]
    database_url: str
    sqlite_path: str


def sqlite_db_path_for_runtime(*, override: str | None, in_container: bool, package_dir: Path) -> str:
    override = (override or "").strip()
    if override:
        return override
    if in_container:
        return "/app/data/database.db"
    return str(package_dir / "data" / "database.db")


def sqlite_db_path() -> str:
    package_dir = Path(__file__).resolve().parent
    override = os.environ.get("SQLITE_DB_PATH") or os.environ.get("SQLITE_PATH")
    return sqlite_db_path_for_runtime(
        override=override,
        in_container=os.path.exists("/app"),
        package_dir=package_dir,
    )


def load_db_config_from_env(env: Mapping[str, str], *, sqlite_path: str) -> DbConfig:
    backend = (env.get("DB_BACKEND") or "").strip().lower()
    dsn = (env.get("DATABASE_URL") or env.get("POSTGRES_DSN") or "").strip() or None

    if backend in {"postgres", "postgresql"}:
        if not dsn:
            raise RuntimeError("PostgreSQL backend requested but DATABASE_URL/POSTGRES_DSN is not set")
        return DbConfig(backend="postgres", database_url=dsn, sqlite_path=sqlite_path)

    if backend == "sqlite":
        return DbConfig(backend="sqlite", database_url=f"sqlite:///{sqlite_path}", sqlite_path=sqlite_path)

    if dsn:
        return DbConfig(backend="postgres", database_url=dsn, sqlite_path=sqlite_path)

    return DbConfig(backend="sqlite", database_url=f"sqlite:///{sqlite_path}", sqlite_path=sqlite_path)


def load_db_config() -> DbConfig:
    return load_db_config_from_env(os.environ, sqlite_path=sqlite_db_path())

