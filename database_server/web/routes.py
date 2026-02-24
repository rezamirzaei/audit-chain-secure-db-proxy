from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask

from .auth_routes import DatabaseAuthRoutes
from .page_routes import DatabasePageRoutes


class DatabaseWebRoutes:
    """Register database server HTML routes.

    This is intentionally a thin facade so auth and page routes can evolve
    independently while keeping the `DatabaseWebRoutes` injection contract stable.
    """

    def __init__(
        self,
        *,
        app: Flask,
        runtime: Any,
        get_db: Callable[[], Any],
        login_required: Callable[[Any], Any],
        log_action: Callable[..., None],
        is_rate_limited: Callable[[str], bool],
        record_failed_attempt: Callable[[str], None],
        complete_login: Callable[[], None],
        debug_log: Callable[..., None] | None = None,
    ) -> None:
        self.app = app
        self.runtime = runtime
        self.get_db = get_db
        self.login_required = login_required
        self.log_action = log_action
        self.is_rate_limited = is_rate_limited
        self.record_failed_attempt = record_failed_attempt
        self.complete_login = complete_login
        self.debug_log = debug_log

    def register(self) -> None:
        DatabaseAuthRoutes(
            app=self.app,
            runtime=self.runtime,
            get_db=self.get_db,
            log_action=self.log_action,
            is_rate_limited=self.is_rate_limited,
            record_failed_attempt=self.record_failed_attempt,
            complete_login=self.complete_login,
            debug_log=self.debug_log,
        ).register()

        DatabasePageRoutes(
            app=self.app,
            runtime=self.runtime,
            get_db=self.get_db,
            login_required=self.login_required,
        ).register()

