from __future__ import annotations

from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

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

JsonBody = dict[str, Any]
JsonResponse = tuple[JsonBody, int]

LOGIN_BUCKET = "login"
INVALID_SESSION_STATE_MESSAGE = "Invalid session state. Start from login."
AUTH_USERS_TABLE = "auth_users"


class PasswordServiceLike(Protocol):
    def verify_and_upgrade(self, session: Any, user: Any, field: str, provided: str) -> bool: ...


class TotpServiceLike(Protocol):
    def verify(self, secret: str, token: str, window: int = 1) -> bool: ...


class AuthUserLike(Protocol):
    id: int
    username: str
    role: str
    totp_enabled: bool | None
    totp_secret: str | None
    security_question: str | None


@dataclass
class ApiResponseFactory:
    session_store: MutableMapping[str, Any]

    @staticmethod
    def model(model: Any) -> JsonBody:
        return model.model_dump(mode="json")

    def error(self, error: str, status: int, message: str | None = None) -> JsonResponse:
        return self.model(ApiErrorResponse(error=error, message=message)), status

    def invalid_session_state(self) -> JsonResponse:
        return self.error(INVALID_SESSION_STATE_MESSAGE, 400)

    def current_authenticated_user(self) -> AuthenticatedUser:
        return AuthenticatedUser(
            id=int(self.session_store["user_id"]),
            username=str(self.session_store["username"]),
            role=str(self.session_store["role"]),
        )

    def login_success(self) -> JsonResponse:
        return (
            self.model(
                LoginSuccessResponse(
                    success=True,
                    authenticated=True,
                    user=self.current_authenticated_user(),
                )
            ),
            200,
        )

    def login_step(
        self,
        *,
        next_step: Literal["totp", "security"],
        message: str,
        requires_2fa: bool | None = None,
        security_question: str | None = None,
    ) -> JsonResponse:
        return (
            self.model(
                LoginStepResponse(
                    success=True,
                    next_step=next_step,
                    message=message,
                    requires_2fa=requires_2fa,
                    security_question=security_question,
                )
            ),
            200,
        )


@dataclass
class LoginSessionState:
    session_store: MutableMapping[str, Any]

    def pending_user_id(self) -> int | None:
        raw_user_id = self.session_store.get("pending_user_id")
        if raw_user_id is None:
            return None
        try:
            return int(raw_user_id)
        except (TypeError, ValueError):
            return None

    def set_password_verified(self, user: AuthUserLike) -> None:
        self.session_store["pending_user_id"] = user.id
        self.session_store["pending_username"] = user.username
        self.session_store["pending_role"] = user.role
        self.session_store["pending_totp_enabled"] = user.totp_enabled
        self.session_store["auth_step"] = "password_verified"

    def mark_totp_verified(self) -> None:
        self.session_store["auth_step"] = "totp_verified"

    def has_expected_step(self, expected_step: str) -> bool:
        return "pending_user_id" in self.session_store and self.session_store.get("auth_step") == expected_step

    def expected_security_step(self) -> str:
        return "totp_verified" if self.session_store.get("pending_totp_enabled") else "password_verified"


@dataclass
class AuthLoginUseCases:
    session_store: MutableMapping[str, Any]
    db_session: Any
    user_service: UserService
    password_service: PasswordServiceLike
    totp_service: TotpServiceLike
    complete_login: Callable[[], None]
    is_rate_limited: Callable[[str], bool]
    record_failed_attempt: Callable[[str], None]
    responses: ApiResponseFactory
    login_state: LoginSessionState

    def login(self, payload: LoginApiRequest) -> JsonResponse:
        if self.is_rate_limited(LOGIN_BUCKET):
            return self.responses.error("Too many login attempts. Please try again later.", 429)

        handlers: dict[str, Callable[[LoginApiRequest], JsonResponse]] = {
            "password": self.login_password,
            "totp": self.login_totp,
            "security": self.login_security,
        }
        handler = handlers.get(payload.step)
        if handler is None:
            return self.responses.error(f"Unknown step: {payload.step}", 400)
        return handler(payload)

    def login_password(self, payload: LoginApiRequest) -> JsonResponse:
        username = payload.username
        password = payload.password
        if username is None or password is None:
            return self.responses.error("Missing credentials", 400)

        user = self.user_service.get_by_username(username)
        if user is None or not self.password_service.verify_and_upgrade(self.db_session, user, "password", password):
            self.record_login_failure()
            return self.responses.error("Invalid credentials", 401)

        self.login_state.set_password_verified(user)

        if user.totp_enabled:
            return self.responses.login_step(
                next_step="totp",
                message="Password verified. Please provide 2FA code.",
                requires_2fa=True,
            )

        if user.security_question:
            return self.responses.login_step(
                next_step="security",
                security_question=user.security_question,
                message="Password verified. Please answer security question.",
            )

        return self.complete_login_and_success()

    def login_totp(self, payload: LoginApiRequest) -> JsonResponse:
        if not self.login_state.has_expected_step("password_verified"):
            return self.responses.invalid_session_state()

        totp_code = payload.totp_code or ""
        format_error = self.validate_totp_code(totp_code)
        if format_error is not None:
            return format_error

        user, error_response = self.require_pending_user()
        if error_response is not None:
            return error_response

        if not user.totp_secret or not self.totp_service.verify(user.totp_secret, totp_code):
            self.record_login_failure()
            return self.responses.error("Invalid 2FA code", 401)

        self.login_state.mark_totp_verified()
        return self.continue_to_security_or_complete(user, verified_message="2FA verified. Please answer security question.")

    def login_security(self, payload: LoginApiRequest) -> JsonResponse:
        if not self.login_state.has_expected_step(self.login_state.expected_security_step()):
            return self.responses.invalid_session_state()

        user, error_response = self.require_pending_user()
        if error_response is not None:
            return error_response

        answer = (payload.security_answer or "").lower()
        if not self.password_service.verify_and_upgrade(self.db_session, user, "security_answer", answer):
            self.record_login_failure()
            return self.responses.error("Incorrect security answer", 401)

        return self.complete_login_and_success()

    def complete_login_and_success(self) -> JsonResponse:
        self.complete_login()
        return self.responses.login_success()

    def continue_to_security_or_complete(self, user: AuthUserLike, *, verified_message: str) -> JsonResponse:
        if user.security_question:
            return self.responses.login_step(
                next_step="security",
                security_question=user.security_question,
                message=verified_message,
            )
        return self.complete_login_and_success()

    def require_pending_user(self) -> tuple[AuthUserLike | None, JsonResponse | None]:
        user_id = self.login_state.pending_user_id()
        if user_id is None:
            return None, self.responses.invalid_session_state()

        user = self.user_service.get_by_id(user_id)
        if user is None:
            return None, self.responses.invalid_session_state()
        return user, None

    def validate_totp_code(self, totp_code: str) -> JsonResponse | None:
        if not totp_code or not totp_code.isdigit() or len(totp_code) != 6:
            self.record_login_failure()
            return self.responses.error("Invalid 2FA code format. Code must be exactly 6 digits.", 400)
        return None

    def record_login_failure(self) -> None:
        self.record_failed_attempt(LOGIN_BUCKET)


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


class DatabaseApiService:
    """Facade exposing the API methods expected by Flask blueprints."""

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
        password_service: PasswordServiceLike,
        totp_service: TotpServiceLike,
        complete_login: Callable[[], None],
        is_rate_limited: Callable[[str], bool],
        record_failed_attempt: Callable[[str], None],
        enable_query_console: bool,
    ) -> None:
        # Backward-compatible attribute kept for app-level `log_action()` helper.
        self.audit_service = audit_service

        responses = ApiResponseFactory(session_store=session_store)
        login_state = LoginSessionState(session_store=session_store)

        self.auth = AuthLoginUseCases(
            session_store=session_store,
            db_session=db_session,
            user_service=user_service,
            password_service=password_service,
            totp_service=totp_service,
            complete_login=complete_login,
            is_rate_limited=is_rate_limited,
            record_failed_attempt=record_failed_attempt,
            responses=responses,
            login_state=login_state,
        )
        self.query_console = QueryConsoleUseCases(
            session_store=session_store,
            audit_service=audit_service,
            schema_service=schema_service,
            query_service=query_service,
            table_service=table_service,
            enable_query_console=enable_query_console,
            responses=responses,
        )

    def login(self, payload: LoginApiRequest) -> JsonResponse:
        return self.auth.login(payload)

    def tables(self) -> JsonResponse:
        return self.query_console.tables()

    def query(self, payload: QueryApiRequest) -> JsonResponse:
        return self.query_console.query(payload)

    def table_data(self, table_name: str, limit: int, offset: int) -> JsonResponse:
        return self.query_console.table_data(table_name, limit, offset)

    def audit_verify(self) -> JsonBody:
        return self.query_console.audit_verify()
