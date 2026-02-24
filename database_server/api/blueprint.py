from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from flask import Blueprint, jsonify, request, session
from sqlalchemy import select

from ..models import AuthUser

DecoratorFunc = Callable[[Any], Any]
ApiServiceFactory = Callable[[], Any]


@dataclass(frozen=True)
class DatabaseApiBlueprintDependencies:
    request_validator: Any
    login_request_model: Any
    query_request_model: Any
    table_path_model: Any
    table_pagination_model: Any
    health_response_model: Any
    session_response_model: Any
    totp_response_model: Any
    logout_response_model: Any
    api_service_factory: ApiServiceFactory
    enable_totp_test_endpoint: bool
    get_db: Callable[[], Any]
    get_totp_token: Callable[[str], str]
    login_required: DecoratorFunc
    log_action: Callable[..., None]


class RequestValidatorLike(Protocol):
    def parse_json(self, request_obj: Any, model: Any) -> Any: ...
    def parse_mapping(self, payload: dict[str, Any], model: Any, *, source: str) -> Any: ...


class DatabaseApiController:
    def __init__(self, deps: DatabaseApiBlueprintDependencies) -> None:
        self.deps = deps
        self.request_validator: RequestValidatorLike = deps.request_validator
        self.login_request_model = deps.login_request_model
        self.query_request_model = deps.query_request_model
        self.table_path_model = deps.table_path_model
        self.table_pagination_model = deps.table_pagination_model
        self.health_response_model = deps.health_response_model
        self.session_response_model = deps.session_response_model
        self.totp_response_model = deps.totp_response_model
        self.logout_response_model = deps.logout_response_model

    def api_service(self) -> Any:
        return self.deps.api_service_factory()

    def health(self):
        payload = self.health_response_model(
            status="healthy",
            timestamp=datetime.now().isoformat(),
            database="connected",
        )
        return jsonify(payload.model_dump(mode="json"))

    def session_info(self):
        if "user_id" not in session:
            payload = self.session_response_model(authenticated=False)
            return jsonify(payload.model_dump(mode="json"))

        payload = self.session_response_model(
            authenticated=True,
            user_id=int(session["user_id"]),
            username=str(session["username"]),
            role=str(session["role"]),
            login_time=session.get("login_time"),
        )
        return jsonify(payload.model_dump(mode="json"))

    def login(self):
        payload = self.request_validator.parse_json(request, self.login_request_model)
        body, status = self.api_service().login(payload)
        return jsonify(body), status

    def totp_current(self):
        if not self.deps.enable_totp_test_endpoint:
            return jsonify({"error": "Not found"}), 404

        username = request.args.get("username", "admin")
        db_session = self.deps.get_db()
        secret = db_session.execute(
            select(AuthUser.totp_secret).where(AuthUser.username == username)
        ).scalar_one_or_none()
        if secret:
            payload = self.totp_response_model(
                username=username,
                totp_token=self.deps.get_totp_token(secret),
                valid_for_seconds=30 - (int(time.time()) % 30),
            )
            return jsonify(payload.model_dump(mode="json"))
        return jsonify({"error": "User not found"}), 404

    def logout(self):
        self.deps.log_action("api_logout")
        session.clear()
        payload = self.logout_response_model(success=True)
        return jsonify(payload.model_dump(mode="json"))

    def tables(self):
        body, status = self.api_service().tables()
        return jsonify(body), status

    def query(self):
        payload = self.request_validator.parse_json(request, self.query_request_model)
        body, status = self.api_service().query(payload)
        return jsonify(body), status

    def table_data(self, table_name: str):
        path_params = self.request_validator.parse_mapping(
            {"table_name": table_name},
            self.table_path_model,
            source="path",
        )
        page_params = self.request_validator.parse_mapping(
            {"limit": request.args.get("limit", 100), "offset": request.args.get("offset", 0)},
            self.table_pagination_model,
            source="query",
        )
        body, status = self.api_service().table_data(
            path_params.table_name,
            page_params.limit,
            page_params.offset,
        )
        return jsonify(body), status

    def audit_verify(self):
        if session.get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return jsonify(self.api_service().audit_verify())


def create_api_blueprint(deps: DatabaseApiBlueprintDependencies) -> Blueprint:
    bp = Blueprint("database_api", __name__, url_prefix="/api")
    controller = DatabaseApiController(deps)
    login_required = deps.login_required

    bp.add_url_rule("/health", endpoint="api_health", view_func=controller.health, methods=["GET"])
    bp.add_url_rule("/session", endpoint="api_session", view_func=controller.session_info, methods=["GET"])
    bp.add_url_rule("/login", endpoint="api_login", view_func=controller.login, methods=["POST"])
    bp.add_url_rule("/totp/current", endpoint="api_totp_current", view_func=controller.totp_current, methods=["GET"])
    bp.add_url_rule("/logout", endpoint="api_logout", view_func=login_required(controller.logout), methods=["POST"])
    bp.add_url_rule("/tables", endpoint="api_tables", view_func=login_required(controller.tables), methods=["GET"])
    bp.add_url_rule("/query", endpoint="api_query", view_func=login_required(controller.query), methods=["POST"])
    bp.add_url_rule(
        "/table/<table_name>",
        endpoint="api_table_data",
        view_func=login_required(controller.table_data),
        methods=["GET"],
    )
    bp.add_url_rule(
        "/audit/verify",
        endpoint="api_audit_verify",
        view_func=login_required(controller.audit_verify),
        methods=["GET"],
    )

    return bp
