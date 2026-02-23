from __future__ import annotations

from datetime import datetime
import time
from typing import Any

from flask import Blueprint, jsonify, request, session


def create_api_blueprint(deps: dict[str, Any]) -> Blueprint:
    bp = Blueprint("database_api", __name__, url_prefix="/api")

    request_validator = deps["request_validator"]
    login_request_model = deps["login_request_model"]
    query_request_model = deps["query_request_model"]
    table_path_model = deps["table_path_model"]
    table_pagination_model = deps["table_pagination_model"]
    health_response_model = deps["health_response_model"]
    session_response_model = deps["session_response_model"]
    totp_response_model = deps["totp_response_model"]
    logout_response_model = deps["logout_response_model"]

    @bp.route("/health", methods=["GET"])
    def api_health():
        payload = health_response_model(
            status="healthy",
            timestamp=datetime.now().isoformat(),
            database="connected",
        )
        return jsonify(payload.model_dump(mode="json"))

    @bp.route("/session", methods=["GET"])
    def api_session():
        if "user_id" not in session:
            payload = session_response_model(authenticated=False)
            return jsonify(payload.model_dump(mode="json"))

        payload = session_response_model(
            authenticated=True,
            user_id=int(session["user_id"]),
            username=str(session["username"]),
            role=str(session["role"]),
            login_time=session.get("login_time"),
        )
        return jsonify(payload.model_dump(mode="json"))

    @bp.route("/login", methods=["POST"])
    def api_login():
        payload = request_validator.parse_json(request, login_request_model)
        body, status = deps["api_service_factory"]().login(payload)
        return jsonify(body), status

    @bp.route("/totp/current", methods=["GET"])
    def api_totp_current():
        if not deps["enable_totp_test_endpoint"]:
            return jsonify({"error": "Not found"}), 404

        username = request.args.get("username", "admin")
        db = deps["get_db"]()
        user = db.execute("SELECT totp_secret FROM auth_users WHERE username = ?", (username,)).fetchone()
        if user and user["totp_secret"]:
            payload = totp_response_model(
                username=username,
                totp_token=deps["get_totp_token"](user["totp_secret"]),
                valid_for_seconds=30 - (int(time.time()) % 30),
            )
            return jsonify(payload.model_dump(mode="json"))
        return jsonify({"error": "User not found"}), 404

    @bp.route("/logout", methods=["POST"])
    @deps["login_required"]
    def api_logout():
        deps["log_action"]("api_logout")
        session.clear()
        payload = logout_response_model(success=True)
        return jsonify(payload.model_dump(mode="json"))

    @bp.route("/tables", methods=["GET"])
    @deps["login_required"]
    def api_tables():
        body, status = deps["api_service_factory"]().tables()
        return jsonify(body), status

    @bp.route("/query", methods=["POST"])
    @deps["login_required"]
    def api_query():
        payload = request_validator.parse_json(request, query_request_model)
        body, status = deps["api_service_factory"]().query(payload)
        return jsonify(body), status

    @bp.route("/table/<table_name>", methods=["GET"])
    @deps["login_required"]
    def api_table_data(table_name: str):
        path_params = request_validator.parse_mapping({"table_name": table_name}, table_path_model, source="path")
        page_params = request_validator.parse_mapping(
            {"limit": request.args.get("limit", 100), "offset": request.args.get("offset", 0)},
            table_pagination_model,
            source="query",
        )
        body, status = deps["api_service_factory"]().table_data(
            path_params.table_name,
            page_params.limit,
            page_params.offset,
        )
        return jsonify(body), status

    @bp.route("/audit/verify", methods=["GET"])
    @deps["login_required"]
    def api_audit_verify():
        if session.get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        valid, info = deps["verify_audit_chain"]()
        return jsonify(deps["api_service_factory"]().audit_verify(valid, info))

    return bp
