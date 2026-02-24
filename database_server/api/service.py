from __future__ import annotations

from collections.abc import Callable, MutableMapping
from typing import Any

from .auth_use_cases import AuthLoginUseCases
from .query_use_cases import QueryConsoleUseCases
from .schemas import LoginApiRequest, QueryApiRequest
from .support import (
    ApiResponseFactory,
    JsonBody,
    JsonResponse,
    LoginSessionState,
    PasswordServiceLike,
    TotpServiceLike,
)
from ..domain import AuditService, QueryService, SchemaService, TableService, UserService


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
