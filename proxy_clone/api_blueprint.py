from __future__ import annotations

from typing import Any

from flask import Blueprint, Response, jsonify, request


def create_api_blueprint(deps: dict[str, Any]) -> Blueprint:
    bp = Blueprint("proxy_api", __name__, url_prefix="/api")

    request_validator = deps["request_validator"]
    connect_request_model = deps["connect_request_model"]
    query_request_model = deps["query_request_model"]
    table_path_model = deps["table_path_model"]

    @bp.route("/health", methods=["GET"])
    @deps["feature_enabled"]
    def api_health():
        return jsonify(deps["api_service_factory"]().health())

    @bp.route("/status", methods=["GET"])
    @deps["feature_enabled"]
    @deps["proxy_status_available"]
    def api_status():
        return jsonify(deps["api_service_factory"]().status())

    @bp.route("/connect", methods=["POST"])
    @deps["feature_enabled"]
    def api_connect():
        payload = request_validator.parse_json(request, connect_request_model)
        body, status = deps["api_service_factory"]().connect(payload)
        return jsonify(body), status

    @bp.route("/query", methods=["POST"])
    @deps["feature_enabled"]
    def api_query():
        vault = deps["vault"]
        if not vault.ensure_session():
            return jsonify({"error": "Not connected to database server"}), 401

        payload = request_validator.parse_json(request, query_request_model)
        response = vault.proxy_request("POST", "/api/query", json={"query": payload.query})
        if response is None:
            return jsonify({"error": "Failed to connect to database server"}), 503
        return Response(response.content, content_type="application/json", status=response.status_code)

    @bp.route("/tables", methods=["GET"])
    @deps["feature_enabled"]
    def api_tables():
        vault = deps["vault"]
        if not vault.ensure_session():
            return jsonify({"error": "Not connected"}), 401

        response = vault.proxy_request("GET", "/api/tables")
        if response is None:
            return jsonify({"error": "Failed to connect"}), 503
        return Response(response.content, content_type="application/json")

    @bp.route("/table/<table_name>", methods=["GET"])
    @deps["feature_enabled"]
    def api_table_data(table_name: str):
        vault = deps["vault"]
        if not vault.ensure_session():
            return jsonify({"error": "Not connected"}), 401

        path_params = request_validator.parse_mapping({"table_name": table_name}, table_path_model, source="path")
        response = vault.proxy_request("GET", f"/api/table/{path_params.table_name}")
        if response is None:
            return jsonify({"error": "Failed to connect"}), 503
        return Response(response.content, content_type="application/json")

    return bp
