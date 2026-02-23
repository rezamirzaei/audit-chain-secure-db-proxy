from __future__ import annotations

import logging
import time
from collections.abc import Callable

from .auth_utils import PasswordService, TotpService
from .bootstrap import AppBootstrap
from .config import AppConfig
from .db import DatabaseSessionManager


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


class DatabaseServerRuntime:
    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config or AppConfig.from_env()
        self.bootstrap = AppBootstrap(self.config)
        self.app = self.bootstrap.create_app()

        logging.basicConfig(level=self.config.log_level)
        self.logger = logging.getLogger("database_server")

        self.db_manager = DatabaseSessionManager.from_env()
        self.password_service = PasswordService()
        self.totp_service = TotpService()
        self.rate_limiter = InMemoryRateLimiter(
            window_seconds=self.config.rate_limit_window_seconds,
            max_attempts=self.config.rate_limit_max_attempts,
        )

