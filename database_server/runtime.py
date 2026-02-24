from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from .auth_utils import PasswordService, TotpService
from .config import AppConfig
from .persistence import DatabaseSessionManager


class InMemoryRateLimiter:
    def __init__(
        self,
        window_seconds: int,
        max_attempts: int,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self._window_seconds = window_seconds
        self._max_attempts = max_attempts
        self._now_fn = now_fn or time.time
        self._attempts: dict[str, dict[str, list[float]]] = {}

    def is_limited(self, bucket: str, key: str) -> bool:
        now = self._now_fn()
        active = [ts for ts in self._attempts.get(bucket, {}).get(key, []) if now - ts < self._window_seconds]
        self._attempts.setdefault(bucket, {})[key] = active
        return len(active) >= self._max_attempts

    def record_failure(self, bucket: str, key: str) -> None:
        now = self._now_fn()
        entries = self._attempts.setdefault(bucket, {}).setdefault(key, [])
        entries.append(now)


@dataclass(frozen=True)
class DatabaseServerRuntime:
    config: AppConfig
    logger: logging.Logger
    db_manager: DatabaseSessionManager
    password_service: PasswordService
    totp_service: TotpService
    rate_limiter: InMemoryRateLimiter


def create_runtime(
    config: AppConfig | None = None,
    *,
    db_manager: DatabaseSessionManager | None = None,
    password_service: PasswordService | None = None,
    totp_service: TotpService | None = None,
    rate_limiter: InMemoryRateLimiter | None = None,
) -> DatabaseServerRuntime:
    config = config or AppConfig.from_env()

    logging.basicConfig(level=config.log_level)
    logger = logging.getLogger("database_server")

    db_manager = db_manager or DatabaseSessionManager.from_env()
    password_service = password_service or PasswordService()
    totp_service = totp_service or TotpService()
    rate_limiter = rate_limiter or InMemoryRateLimiter(
        window_seconds=config.rate_limit_window_seconds,
        max_attempts=config.rate_limit_max_attempts,
    )
    return DatabaseServerRuntime(
        config=config,
        logger=logger,
        db_manager=db_manager,
        password_service=password_service,
        totp_service=totp_service,
        rate_limiter=rate_limiter,
    )
