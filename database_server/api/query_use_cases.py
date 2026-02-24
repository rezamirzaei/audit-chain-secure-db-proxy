from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Any

from .schemas import (
    AuditVerifyResponse,
    QueryApiRequest,
    QuerySuccessResponse,
    TableDataResponse,
    TablesResponse,
    TableSummary,
)
from .support import AUTH_USERS_TABLE, ApiResponseFactory, JsonBody, JsonResponse
from ..services import AuditService, QueryService, SchemaService, TableService


@dataclass
class QueryConsoleUseCases:
    session_store: MutableMapping[str, Any]
    audit_service: AuditService
    schema_service: SchemaService
    query_service: QueryService
    table_service: TableService
    enable_query_console: bool
    responses: ApiResponseFactory

    def tables(self) -> JsonResponse:
        feature_error = self.require_console_enabled()
        if feature_error is not None:
            return feature_error

        summaries: list[TableSummary] = []
        for table_name in self.schema_service.list_tables():
            if table_name == AUTH_USERS_TABLE:
                continue
            total, _ = self.table_service.get_table_data(table_name, limit=1, offset=0)
            columns = self.schema_service.table_columns(table_name)
            summaries.append(TableSummary(name=table_name, row_count=total, columns=columns))

        return self.responses.model(TablesResponse(tables=summaries)), 200

    def query(self, payload: QueryApiRequest) -> JsonResponse:
        feature_error = self.require_console_enabled()
        if feature_error is not None:
            return feature_error

        policy_error = self.readonly_query_policy_error(payload.query)
        if policy_error is not None:
            return policy_error

        try:
            columns, rows = self.query_service.execute_readonly(payload.query)
            self.log_audit(action="query", query=payload.query)
            return (
                self.responses.model(
                    QuerySuccessResponse(
                        success=True,
                        columns=columns,
                        data=rows,
                        row_count=len(rows),
                    )
                ),
                200,
            )
        except Exception as exc:  # pragma: no cover - engine-specific errors
            return self.responses.error(str(exc), 400)

    def table_data(self, table_name: str, limit: int, offset: int) -> JsonResponse:
        feature_error = self.require_console_enabled()
        if feature_error is not None:
            return feature_error
        if table_name == AUTH_USERS_TABLE:
            return self.responses.error("Access denied", 403)

        try:
            if table_name not in self.schema_service.list_tables():
                return self.responses.error("Table not found", 404)

            total, rows = self.table_service.get_table_data(table_name, limit, offset)
            self.log_audit(action="view_table", table_name=table_name)
            return (
                self.responses.model(
                    TableDataResponse(
                        success=True,
                        table=table_name,
                        data=rows,
                        total=total,
                        limit=limit,
                        offset=offset,
                    )
                ),
                200,
            )
        except Exception as exc:  # pragma: no cover - engine-specific errors
            return self.responses.error(str(exc), 400)

    def audit_verify(self) -> JsonBody:
        valid, info = self.audit_service.verify_chain()
        return AuditVerifyResponse(valid=valid, info=info).model_dump(mode="json")

    def require_console_enabled(self) -> JsonResponse | None:
        if self.enable_query_console:
            return None
        return self.responses.error("Query console disabled", 403)

    def readonly_query_policy_error(self, query: str) -> JsonResponse | None:
        query_lower = query.lower()
        allowed_prefixes = ("select", "pragma") if self.query_service.backend() == "sqlite" else ("select", "show")
        if not query_lower.startswith(allowed_prefixes):
            return self.responses.error(f"Only {', '.join(allowed_prefixes).upper()} queries are allowed", 403)
        if AUTH_USERS_TABLE in query_lower:
            return self.responses.error("Access denied to this table", 403)
        return None

    def log_audit(self, *, action: str, table_name: str | None = None, query: str | None = None) -> None:
        self.audit_service.log_action(
            user_id=int(self.session_store["user_id"]),
            action=action,
            table_name=table_name,
            query=query,
        )
