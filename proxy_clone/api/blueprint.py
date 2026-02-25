from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from flask import Blueprint, Response, jsonify, request

from shared.request_validation import RequestValidatorLike
from ..state.protocols import ProxyVaultLike

DecoratorFunc = Callable[[Any], Any]
ApiServiceFactory = Callable[[], Any]


@dataclass(frozen=True)
class ProxyApiBlueprintDependencies:
    request_validator: Any
    connect_request_model: Any
    query_request_model: Any
    table_path_model: Any
    api_service_factory: ApiServiceFactory
    feature_enabled: DecoratorFunc
    proxy_status_available: DecoratorFunc
    vault: Any


class ProxyApiController:
    def __init__(self, deps: ProxyApiBlueprintDependencies) -> None:
        self.deps = deps
        self.request_validator: RequestValidatorLike = deps.request_validator
        self.vault: ProxyVaultLike = deps.vault
        self.connect_request_model = deps.connect_request_model
        self.query_request_model = deps.query_request_model
        self.table_path_model = deps.table_path_model

    def api_service(self) -> Any:
        return self.deps.api_service_factory()

    def require_proxy_session(
        self, not_connected_message: str
    ) -> tuple[ProxyVaultLike | None, tuple[Any, int] | None]:
        if self.vault.ensure_session():
            return self.vault, None
        return None, (jsonify({"error": not_connected_message}), 401)

    @staticmethod
    def json_proxy_response(response: Any, *, failure_message: str) -> Response | tuple[Any, int]:
        if response is None:
            return jsonify({"error": failure_message}), 503
        return Response(response.content, content_type="application/json", status=response.status_code)

    def health(self):
        return jsonify(self.api_service().health())

    def status(self):
        return jsonify(self.api_service().status())

    def connect(self):
        payload = self.request_validator.parse_json(request, self.connect_request_model)
        body, status = self.api_service().connect(payload)
        return jsonify(body), status

    def query(self):
        vault, error_response = self.require_proxy_session("Not connected to database server")
        if error_response is not None:
            return error_response
        assert vault is not None

        payload = self.request_validator.parse_json(request, self.query_request_model)
        response = vault.proxy_request("POST", "/api/query", json={"query": payload.query})
        return self.json_proxy_response(response, failure_message="Failed to connect to database server")

    def tables(self):
        vault, error_response = self.require_proxy_session("Not connected")
        if error_response is not None:
            return error_response
        assert vault is not None

        response = vault.proxy_request("GET", "/api/tables")
        return self.json_proxy_response(response, failure_message="Failed to connect")

    def table_data(self, table_name: str):
        vault, error_response = self.require_proxy_session("Not connected")
        if error_response is not None:
            return error_response
        assert vault is not None

        path_params = self.request_validator.parse_mapping(
            {"table_name": table_name},
            self.table_path_model,
            source="path",
        )
        response = vault.proxy_request("GET", f"/api/table/{path_params.table_name}")
        return self.json_proxy_response(response, failure_message="Failed to connect")


def create_api_blueprint(deps: ProxyApiBlueprintDependencies) -> Blueprint:
    bp = Blueprint("proxy_api", __name__, url_prefix="/api")
    controller = ProxyApiController(deps)

    feature_enabled = deps.feature_enabled
    proxy_status_available = deps.proxy_status_available

    # Health should be available even when proxy features are disabled (for Docker/CI liveness checks).
    bp.add_url_rule("/health", endpoint="api_health", view_func=controller.health, methods=["GET"])
    bp.add_url_rule(
        "/status",
        endpoint="api_status",
        view_func=feature_enabled(proxy_status_available(controller.status)),
        methods=["GET"],
    )
    bp.add_url_rule(
        "/connect",
        endpoint="api_connect",
        view_func=feature_enabled(controller.connect),
        methods=["POST"],
    )
    bp.add_url_rule(
        "/query",
        endpoint="api_query",
        view_func=feature_enabled(controller.query),
        methods=["POST"],
    )
    bp.add_url_rule(
        "/tables",
        endpoint="api_tables",
        view_func=feature_enabled(controller.tables),
        methods=["GET"],
    )
    bp.add_url_rule(
        "/table/<table_name>",
        endpoint="api_table_data",
        view_func=feature_enabled(controller.table_data),
        methods=["GET"],
    )

    return bp
