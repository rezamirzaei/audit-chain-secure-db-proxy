from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from flask import Flask

from .connect_routes import (
    CONNECT_STEP_CREDENTIALS as CONNECT_STEP_CREDENTIALS,
    CONNECT_STEP_SECURITY as CONNECT_STEP_SECURITY,
    CONNECT_STEP_TOTP as CONNECT_STEP_TOTP,
    VALID_CONNECT_STEPS as VALID_CONNECT_STEPS,
    ConnectStep as ConnectStep,
    ProxyConnectController,
    connect_step_request_value,
    normalize_connect_step,
    totp_validation_error,
)
from .mirror_routes import (
    PROXY_MIRROR_BANNER_HTML as PROXY_MIRROR_BANNER_HTML,
    ProxyMirrorController,
    mirror_api_request_params,
    rewrite_mirrored_html,
)
from .types import ProxyVaultLike


class ProxyWebController:
    def __init__(
        self,
        *,
        vault: ProxyVaultLike,
        drop_current_vault: Callable[[], None],
        debug: Callable[..., None],
        proxy_features_enabled: bool,
    ) -> None:
        self.connect_controller = ProxyConnectController(
            vault=vault,
            drop_current_vault=drop_current_vault,
            debug=debug,
            proxy_features_enabled=proxy_features_enabled,
        )
        self.mirror_controller = ProxyMirrorController(vault=vault, debug=debug)

    @staticmethod
    def connect_step_request_value() -> str:
        return connect_step_request_value()

    @staticmethod
    def normalize_connect_step(step: str) -> ConnectStep:
        return normalize_connect_step(step)

    @staticmethod
    def totp_validation_error(totp_code: str) -> str | None:
        return totp_validation_error(totp_code)

    @staticmethod
    def rewrite_mirrored_html(content: str) -> str:
        return rewrite_mirrored_html(content)

    @staticmethod
    def mirror_api_request_params() -> tuple[str, dict[str, Any]]:
        return mirror_api_request_params()

    def home(self):
        return self.connect_controller.home()

    def connect(self):
        return self.connect_controller.connect()

    def disconnect(self):
        return self.connect_controller.disconnect()

    def mirror(self, path: str = ""):
        return self.mirror_controller.mirror(path=path)

    def mirror_api(self, path: str):
        return self.mirror_controller.mirror_api(path=path)


@dataclass(frozen=True)
class ProxyWebRouteDependencies:
    vault: ProxyVaultLike
    feature_enabled: Callable[[Any], Any]
    proxy_authenticated: Callable[[Any], Any]
    drop_current_vault: Callable[[], None]
    debug: Callable[..., None]
    proxy_features_enabled: bool


def register_web_routes(app: Flask, deps: ProxyWebRouteDependencies) -> None:
    controller = ProxyWebController(
        vault=deps.vault,
        drop_current_vault=deps.drop_current_vault,
        debug=deps.debug,
        proxy_features_enabled=deps.proxy_features_enabled,
    )
    feature_enabled = deps.feature_enabled
    proxy_authenticated = deps.proxy_authenticated

    app.add_url_rule("/", endpoint="home", view_func=controller.home)
    app.add_url_rule(
        "/connect",
        endpoint="connect",
        view_func=feature_enabled(controller.connect),
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/disconnect",
        endpoint="disconnect",
        view_func=feature_enabled(controller.disconnect),
        methods=["POST"],
    )

    mirror_view = feature_enabled(proxy_authenticated(controller.mirror))
    app.add_url_rule("/mirror/", endpoint="mirror", view_func=mirror_view, defaults={"path": ""})
    app.add_url_rule("/mirror/<path:path>", endpoint="mirror", view_func=mirror_view)

    mirror_api_view = feature_enabled(proxy_authenticated(controller.mirror_api))
    app.add_url_rule(
        "/mirror/api/<path:path>",
        endpoint="mirror_api",
        view_func=mirror_api_view,
        methods=["GET", "POST"],
    )
