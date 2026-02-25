"""
Database Server service entrypoint.

This module intentionally exposes a real Flask application factory (`create_app`)
so tests and WSGI servers can create isolated app instances with injected
dependencies.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, MutableMapping, cast

from flask import Flask, g, request, session

from ..api import (
    DatabaseApiBlueprintDependencies,
    DatabaseApiService,
    LoginSessionState,
    RequestPayloadValidationError,
    RequestValidator,
    create_api_blueprint,
)
from ..api.schemas import (
    HealthResponse,
    LoginApiRequest,
    LogoutResponse,
    QueryApiRequest,
    SessionResponse,
    TablePaginationParams,
    TablePathParams,
    TotpCurrentResponse,
)
from .bootstrap import AppBootstrap
from shared.web_common import (
    ContextInjector,
    SecurityHeadersManager,
    enforce_csrf,
    handle_request_validation_error,
    login_required,
)
from .config import AppConfig
from ..persistence.seed import init_db as init_database
from .runtime import DatabaseServerRuntime, create_runtime
from ..domain import AuditService, QueryService, SchemaService, TableService, UserService
from shared.ssl_utils import get_ssl_context
from ..web import DatabaseWebRoutes


@dataclass(frozen=True)
class DatabaseAppContext:
    app: Flask
    runtime: DatabaseServerRuntime
    apply_security_headers: Callable[[Any], Any]

    @property
    def logger(self):
        return self.runtime.logger

    @property
    def config(self) -> AppConfig:
        return self.runtime.config

    def client_ip(self) -> str:
        return request.remote_addr or "unknown"

    def is_rate_limited(self, bucket: str) -> bool:
        return self.runtime.rate_limiter.is_limited(bucket, self.client_ip())

    def record_failed_attempt(self, bucket: str) -> None:
        self.runtime.rate_limiter.record_failure(bucket, self.client_ip())

    def get_db(self) -> Any:
        db_session = getattr(g, "db_session", None)
        if db_session is None:
            db_session = g.db_session = self.runtime.db_manager.session()
        return db_session

    def close_db(self, _exception: BaseException | None = None) -> None:
        db_session = getattr(g, "db_session", None)
        if db_session is not None:
            db_session.close()

    def complete_login(self) -> None:
        session.permanent = True
        LoginSessionState(session_store=cast(MutableMapping[str, Any], session)).finalize_login(
            login_time=datetime.now().isoformat()
        )

        self.log_action("login_complete")

    def log_action(self, action: str, table_name: str | None = None, query: str | None = None) -> None:
        if "user_id" not in session:
            return
        AuditService(self.get_db()).log_action(
            user_id=int(session["user_id"]),
            action=action,
            table_name=table_name,
            query=query,
        )

    def api_service(self) -> DatabaseApiService:
        db_session = self.get_db()
        return DatabaseApiService(
            session_store=cast(MutableMapping[str, Any], session),
            db_session=db_session,
            user_service=UserService(db_session),
            audit_service=AuditService(db_session),
            schema_service=SchemaService(self.runtime.db_manager.engine),
            query_service=QueryService(db_session),
            table_service=TableService(db_session),
            password_service=self.runtime.password_service,
            totp_service=self.runtime.totp_service,
            complete_login=self.complete_login,
            is_rate_limited=self.is_rate_limited,
            record_failed_attempt=self.record_failed_attempt,
            enable_query_console=self.config.enable_query_console,
        )

    def api_blueprint_dependencies(self) -> DatabaseApiBlueprintDependencies:
        return DatabaseApiBlueprintDependencies(
            request_validator=RequestValidator,
            login_request_model=LoginApiRequest,
            query_request_model=QueryApiRequest,
            table_path_model=TablePathParams,
            table_pagination_model=TablePaginationParams,
            health_response_model=HealthResponse,
            session_response_model=SessionResponse,
            totp_response_model=TotpCurrentResponse,
            logout_response_model=LogoutResponse,
            api_service_factory=self.api_service,
            enable_totp_test_endpoint=self.config.enable_totp_test_endpoint,
            get_db=self.get_db,
            get_totp_token=self.runtime.totp_service.get_token,
            login_required=login_required,
            log_action=self.log_action,
        )


def register_app_handlers(app: Flask, ctx: DatabaseAppContext) -> None:
    app.context_processor(lambda: ContextInjector.inject_base_context())
    app.before_request(enforce_csrf)
    app.after_request(ctx.apply_security_headers)
    app.register_error_handler(RequestPayloadValidationError, handle_request_validation_error)
    app.teardown_appcontext(ctx.close_db)


def register_routes(app: Flask, ctx: DatabaseAppContext) -> None:
    web_routes = DatabaseWebRoutes(
        app=app,
        runtime=ctx.runtime,
        get_db=ctx.get_db,
        login_required=login_required,
        log_action=ctx.log_action,
        is_rate_limited=ctx.is_rate_limited,
        record_failed_attempt=ctx.record_failed_attempt,
        complete_login=ctx.complete_login,
    )
    web_routes.register()

    app.register_blueprint(create_api_blueprint(ctx.api_blueprint_dependencies()))


def create_app(
    config: AppConfig | None = None,
    *,
    runtime: DatabaseServerRuntime | None = None,
    init_db: bool = True,
) -> Flask:
    config = config or AppConfig.from_env()
    runtime = runtime or create_runtime(config=config)

    app = AppBootstrap(config).create_app()
    ctx = DatabaseAppContext(
        app=app,
        runtime=runtime,
        apply_security_headers=SecurityHeadersManager.set_security_headers(app),
    )
    app.extensions["runtime"] = runtime
    app.extensions["ctx"] = ctx

    register_app_handlers(app, ctx)
    register_routes(app, ctx)

    if init_db:
        with app.app_context():
            init_database(
                runtime.db_manager,
                demo_mode=config.demo_mode,
                enable_totp_test_endpoint=config.enable_totp_test_endpoint,
                log_info=runtime.logger.info,
            )

    return app


def main() -> None:
    app = create_app()
    runtime: DatabaseServerRuntime = app.extensions["runtime"]

    ssl_cert, ssl_key = get_ssl_context()

    default_port = 5000 if os.path.exists("/app") else 5001
    port = int(os.environ.get("PORT", default_port))

    if ssl_cert and ssl_key:
        runtime.logger.info("Starting server with HTTPS on port %s (cert: %s)...", port, ssl_cert)
        app.run(host="0.0.0.0", port=port, debug=runtime.config.debug_mode, ssl_context=(ssl_cert, ssl_key))
    else:
        runtime.logger.info("SSL certificates not found. Starting server with HTTP on port %s...", port)
        app.run(host="0.0.0.0", port=port, debug=runtime.config.debug_mode)

