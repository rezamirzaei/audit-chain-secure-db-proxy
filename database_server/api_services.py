from __future__ import annotations

from typing import Any, Callable, MutableMapping

from .api_schemas import (
    ApiErrorResponse,
    AuditVerifyResponse,
    AuthenticatedUser,
    LoginApiRequest,
    LoginStepResponse,
    LoginSuccessResponse,
    QueryApiRequest,
    QuerySuccessResponse,
    TableDataResponse,
    TablesResponse,
    TableSummary,
)
from .services import AuditService, QueryService, SchemaService, TableService, UserService


class DatabaseApiService:
    """Encapsulates database-service JSON API business logic."""

    def __init__(
        self,
        *,
        session_store: MutableMapping[str, Any],
        db_session: Any,
        user_service: UserService,
        audit_service: AuditService,
        schema_service: SchemaService,
        query_service: QueryService,
        table_service: TableService,
        password_service: Any,
        totp_service: Any,
        complete_login: Callable[[], None],
        is_rate_limited: Callable[[str], bool],
        record_failed_attempt: Callable[[str], None],
        enable_query_console: bool,
    ):
        self.session = session_store
        self.db_session = db_session
        self.user_service = user_service
        self.audit_service = audit_service
        self.schema_service = schema_service
        self.query_service = query_service
        self.table_service = table_service
        self.password_service = password_service
        self.totp_service = totp_service
        self._complete_login = complete_login
        self._is_rate_limited = is_rate_limited
        self._record_failed_attempt = record_failed_attempt
        self._enable_query_console = enable_query_console

    @staticmethod
    def _dump(model: Any) -> dict[str, Any]:
        return model.model_dump(mode="json")

    def _error(self, error: str, status: int, message: str | None = None) -> tuple[dict[str, Any], int]:
        return self._dump(ApiErrorResponse(error=error, message=message)), status

    def login(self, payload: LoginApiRequest) -> tuple[dict[str, Any], int]:
        if self._is_rate_limited("login"):
            return self._error("Too many login attempts. Please try again later.", 429)

        if payload.step == "password":
            return self._login_password(payload)
        if payload.step == "totp":
            return self._login_totp(payload)
        if payload.step == "security":
            return self._login_security(payload)
        return self._error(f"Unknown step: {payload.step}", 400)

    def _login_password(self, payload: LoginApiRequest) -> tuple[dict[str, Any], int]:
        username = payload.username
        password = payload.password
        if username is None or password is None:
            return self._error("Missing credentials", 400)

        user = self.user_service.get_by_username(username)

        if not user or not self.password_service.verify_and_upgrade(self.db_session, user, "password", password):
            self._record_failed_attempt("login")
            return self._error("Invalid credentials", 401)

        self.session["pending_user_id"] = user.id
        self.session["pending_username"] = user.username
        self.session["pending_role"] = user.role
        self.session["pending_totp_enabled"] = user.totp_enabled
        self.session["auth_step"] = "password_verified"

        if user.totp_enabled:
            return (
                self._dump(
                    LoginStepResponse(
                        success=True,
                        next_step="totp",
                        message="Password verified. Please provide 2FA code.",
                        requires_2fa=True,
                    )
                ),
                200,
            )

        if user.security_question:
            return (
                self._dump(
                    LoginStepResponse(
                        success=True,
                        next_step="security",
                        security_question=user.security_question,
                        message="Password verified. Please answer security question.",
                    )
                ),
                200,
            )

        self._complete_login()
        return (
            self._dump(
                LoginSuccessResponse(
                    success=True,
                    authenticated=True,
                    user=AuthenticatedUser(id=user.id, username=user.username, role=user.role),
                )
            ),
            200,
        )

    def _login_totp(self, payload: LoginApiRequest) -> tuple[dict[str, Any], int]:
        if "pending_user_id" not in self.session or self.session.get("auth_step") != "password_verified":
            return self._error("Invalid session state. Start from login.", 400)

        totp_code = payload.totp_code or ""
        if not totp_code or not totp_code.isdigit() or len(totp_code) != 6:
            self._record_failed_attempt("login")
            return self._error("Invalid 2FA code format. Code must be exactly 6 digits.", 400)

        pending_user_id = self.session.get("pending_user_id")
        if pending_user_id is None:
            return self._error("Invalid session state. Start from login.", 400)
        try:
            user_id = int(pending_user_id)
        except (TypeError, ValueError):
            return self._error("Invalid session state. Start from login.", 400)

        user = self.user_service.get_by_id(user_id)
        if not user:
            return self._error("Invalid session state. Start from login.", 400)

        if not user.totp_secret or not self.totp_service.verify(user.totp_secret, totp_code):
            self._record_failed_attempt("login")
            return self._error("Invalid 2FA code", 401)

        self.session["auth_step"] = "totp_verified"

        if user.security_question:
            return (
                self._dump(
                    LoginStepResponse(
                        success=True,
                        next_step="security",
                        security_question=user.security_question,
                        message="2FA verified. Please answer security question.",
                    )
                ),
                200,
            )

        self._complete_login()
        return (
            self._dump(
                LoginSuccessResponse(
                    success=True,
                    authenticated=True,
                    user=AuthenticatedUser(
                        id=int(self.session["user_id"]),
                        username=str(self.session["username"]),
                        role=str(self.session["role"]),
                    ),
                )
            ),
            200,
        )

    def _login_security(self, payload: LoginApiRequest) -> tuple[dict[str, Any], int]:
        expected_step = "totp_verified" if self.session.get("pending_totp_enabled") else "password_verified"
        if "pending_user_id" not in self.session or self.session.get("auth_step") != expected_step:
            return self._error("Invalid session state. Start from login.", 400)

        answer = (payload.security_answer or "").lower()
        pending_user_id = self.session.get("pending_user_id")
        if pending_user_id is None:
            return self._error("Invalid session state. Start from login.", 400)
        try:
            user_id = int(pending_user_id)
        except (TypeError, ValueError):
            return self._error("Invalid session state. Start from login.", 400)

        user = self.user_service.get_by_id(user_id)
        if not user:
            return self._error("Invalid session state. Start from login.", 400)

        if not self.password_service.verify_and_upgrade(self.db_session, user, "security_answer", answer):
            self._record_failed_attempt("login")
            return self._error("Incorrect security answer", 401)

        self._complete_login()
        return (
            self._dump(
                LoginSuccessResponse(
                    success=True,
                    authenticated=True,
                    user=AuthenticatedUser(
                        id=int(self.session["user_id"]),
                        username=str(self.session["username"]),
                        role=str(self.session["role"]),
                    ),
                )
            ),
            200,
        )

    def tables(self) -> tuple[dict[str, Any], int]:
        if not self._enable_query_console:
            return self._error("Query console disabled", 403)

        summaries: list[TableSummary] = []
        for table_name in self.schema_service.list_tables():
            if table_name == "auth_users":
                continue
            total, _ = self.table_service.get_table_data(table_name, limit=1, offset=0)
            columns = self.schema_service.table_columns(table_name)
            summaries.append(TableSummary(name=table_name, row_count=total, columns=columns))

        return self._dump(TablesResponse(tables=summaries)), 200

    def query(self, payload: QueryApiRequest) -> tuple[dict[str, Any], int]:
        if not self._enable_query_console:
            return self._error("Query console disabled", 403)

        query = payload.query
        query_lower = query.lower()
        allowed_prefixes = ("select", "pragma") if self.query_service.backend() == "sqlite" else ("select", "show")
        if not query_lower.startswith(allowed_prefixes):
            return self._error(f"Only {', '.join(allowed_prefixes).upper()} queries are allowed", 403)
        if "auth_users" in query_lower:
            return self._error("Access denied to this table", 403)

        try:
            columns, rows = self.query_service.execute_readonly(query)
            self.audit_service.log_action(user_id=int(self.session["user_id"]), action="query", table_name=None, query=query)
            return (
                self._dump(
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
            return self._error(str(exc), 400)

    def table_data(self, table_name: str, limit: int, offset: int) -> tuple[dict[str, Any], int]:
        if not self._enable_query_console:
            return self._error("Query console disabled", 403)
        if table_name == "auth_users":
            return self._error("Access denied", 403)

        try:
            if table_name not in self.schema_service.list_tables():
                return self._error("Table not found", 404)

            total, rows = self.table_service.get_table_data(table_name, limit, offset)
            self.audit_service.log_action(user_id=int(self.session["user_id"]), action="view_table", table_name=table_name, query=None)
            return (
                self._dump(
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
            return self._error(str(exc), 400)

    def audit_verify(self) -> dict[str, Any]:
        valid, info = self.audit_service.verify_chain()
        return AuditVerifyResponse(valid=valid, info=info).model_dump(mode="json")
