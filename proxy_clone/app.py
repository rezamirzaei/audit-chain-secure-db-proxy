"""
Proxy Clone service entrypoint.

This module provides a real Flask application factory (`create_app`) so tests
can create isolated proxy instances with injected dependencies.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import Any

from flask import Flask, jsonify, redirect, session, url_for
from werkzeug.local import LocalProxy

from .api_blueprint import ProxyApiBlueprintDependencies, create_api_blueprint
from .api_schemas import ConnectApiRequest, QueryApiRequest, TablePathParams
from .api_services import ProxyApiService
from .api_validation import RequestPayloadValidationError, RequestValidator
from .bootstrap import ProxyCloneBootstrap
from .common import (
    ContextInjector,
    SecurityHeadersManager,
    create_feature_enabled_decorator,
    enforce_csrf,
    handle_request_validation_error,
)
from .config import ProxyCloneConfig
from .runtime import ProxyCloneRuntime, create_runtime
from .ssl_utils import get_ssl_context
from .state.credential_vault import CredentialVault
from .state.vault_registry import VaultRegistry
from .web_routes import ProxyWebRouteDependencies, register_web_routes


@dataclass(frozen=True)
class ProxyCloneAppContext:
    app: Flask
    runtime: ProxyCloneRuntime
    vault_registry: VaultRegistry
    vault: Any
    feature_enabled: Callable[[Any], Any]
    apply_security_headers: Callable[[Any], Any]

    @property
    def config(self) -> ProxyCloneConfig:
        return self.runtime.config

    @property
    def logger(self):
        return self.runtime.logger


def register_app_handlers(app: Flask, ctx: ProxyCloneAppContext) -> None:
    app.context_processor(lambda: ContextInjector.inject_base_context(demo_mode=ctx.config.demo_mode))
    app.before_request(enforce_csrf)
    app.after_request(ctx.apply_security_headers)
    app.register_error_handler(RequestPayloadValidationError, handle_request_validation_error)


def create_app(
    config: ProxyCloneConfig | None = None,
    *,
    runtime: ProxyCloneRuntime | None = None,
) -> Flask:
    config = config or ProxyCloneConfig.from_env()
    runtime = runtime or create_runtime(config=config)

    app = ProxyCloneBootstrap(config).create_app()
    apply_security_headers = SecurityHeadersManager.set_security_headers(app)

    def debug_log(msg: str, *args: Any) -> None:
        if config.debug_mode:
            runtime.logger.debug(msg, *args)

    def create_vault_instance() -> CredentialVault:
        return CredentialVault(
            database_server_url=config.database_server_url,
            ssl_verify=config.ssl_verify,
            debug_log=debug_log,
        )

    vault_registry = VaultRegistry(factory=create_vault_instance)

    def current_vault() -> CredentialVault:
        return vault_registry.current(session)

    def drop_current_vault() -> None:
        vault_registry.drop_current(session)

    vault = LocalProxy(current_vault)

    feature_enabled = create_feature_enabled_decorator(config.proxy_features_enabled)

    def redirect_for_pending_proxy_auth() -> str:
        next_step = vault.auth_state.get("current_step")
        if next_step == "waiting_totp":
            return url_for("connect", step="totp")
        if next_step == "waiting_security":
            return url_for("connect", step="security")
        return url_for("connect")

    def proxy_authenticated(f):
        """Decorator to ensure proxy has valid credentials."""

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not vault.credentials:
                return redirect(url_for("connect"))
            if not vault.ensure_session():
                return redirect(redirect_for_pending_proxy_auth())
            return f(*args, **kwargs)

        return decorated_function

    def proxy_status_available(f):
        """Decorator for API status access after a proxy session has captured credentials."""

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not vault.credentials:
                return jsonify({"error": "Not connected"}), 401
            return f(*args, **kwargs)

        return decorated_function

    def proxy_api_service() -> Any:
        return ProxyApiService(vault=vault, demo_mode=config.demo_mode)

    register_web_routes(
        app,
        ProxyWebRouteDependencies(
            vault=vault,
            feature_enabled=feature_enabled,
            proxy_authenticated=proxy_authenticated,
            drop_current_vault=drop_current_vault,
            debug=debug_log,
            proxy_features_enabled=config.proxy_features_enabled,
        ),
    )

    deps = ProxyApiBlueprintDependencies(
        request_validator=RequestValidator,
        connect_request_model=ConnectApiRequest,
        query_request_model=QueryApiRequest,
        table_path_model=TablePathParams,
        api_service_factory=proxy_api_service,
        feature_enabled=feature_enabled,
        proxy_status_available=proxy_status_available,
        vault=vault,
    )
    app.register_blueprint(create_api_blueprint(deps))

    ctx = ProxyCloneAppContext(
        app=app,
        runtime=runtime,
        vault_registry=vault_registry,
        vault=vault,
        feature_enabled=feature_enabled,
        apply_security_headers=apply_security_headers,
    )
    app.extensions["runtime"] = runtime
    app.extensions["ctx"] = ctx
    app.extensions["vault_registry"] = vault_registry

    register_app_handlers(app, ctx)
    return app


def main() -> None:
    app = create_app()
    runtime: ProxyCloneRuntime = app.extensions["runtime"]

    ssl_cert, ssl_key = get_ssl_context()

    port = int(os.environ.get("PORT", 8080))
    if ssl_cert and ssl_key:
        runtime.logger.info("Starting proxy with HTTPS on port %s (cert: %s)...", port, ssl_cert)
        app.run(host="0.0.0.0", port=port, debug=runtime.config.debug_mode, ssl_context=(ssl_cert, ssl_key))
    else:
        runtime.logger.info("SSL certificates not found. Starting proxy with HTTP on port %s...", port)
        app.run(host="0.0.0.0", port=port, debug=runtime.config.debug_mode)


if __name__ == "__main__":
    main()

