from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, MutableMapping


def _load_sibling_module(module_name: str):
    if __package__:
        return importlib.import_module(f"{__package__}.{module_name}")

    module_path = Path(__file__).with_name(f"{module_name}.py")
    import_name = f"{Path(__file__).parent.name}_{module_name}"
    spec = importlib.util.spec_from_file_location(import_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[import_name] = module
    spec.loader.exec_module(module)
    return module


_api_schemas_module = _load_sibling_module("api_schemas")
ApiErrorResponse = _api_schemas_module.ApiErrorResponse
AuditVerifyResponse = _api_schemas_module.AuditVerifyResponse
AuthenticatedUser = _api_schemas_module.AuthenticatedUser
LoginApiRequest = _api_schemas_module.LoginApiRequest
LoginStepResponse = _api_schemas_module.LoginStepResponse
LoginSuccessResponse = _api_schemas_module.LoginSuccessResponse
QueryApiRequest = _api_schemas_module.QueryApiRequest
QuerySuccessResponse = _api_schemas_module.QuerySuccessResponse
TableDataResponse = _api_schemas_module.TableDataResponse
TablesResponse = _api_schemas_module.TablesResponse
TableSummary = _api_schemas_module.TableSummary


class DatabaseApiService:
    """Encapsulates database-service JSON API business logic."""

    def __init__(
        self,
        *,
        session_store: MutableMapping[str, Any],
        get_db: Callable[[], Any],
        db_list_tables: Callable[[Any], list[str]],
        db_table_columns: Callable[[Any, str], list[str]],
        verify_totp: Callable[[str, str], bool],
        verify_and_upgrade: Callable[[Any, int, str, str, str], bool],
        complete_login: Callable[[], None],
        log_action: Callable[..., None],
        is_rate_limited: Callable[[str], bool],
        record_failed_attempt: Callable[[str], None],
        enable_query_console: bool,
    ):
        self.session = session_store
        self._get_db = get_db
        self._db_list_tables = db_list_tables
        self._db_table_columns = db_table_columns
        self._verify_totp = verify_totp
        self._verify_and_upgrade = verify_and_upgrade
        self._complete_login = complete_login
        self._log_action = log_action
        self._is_rate_limited = is_rate_limited
        self._record_failed_attempt = record_failed_attempt
        self._enable_query_console = enable_query_console

    @staticmethod
    def _dump(model: Any) -> dict[str, Any]:
        return model.model_dump(mode="json")

    def _error(self, error: str, status: int, message: str | None = None) -> tuple[dict[str, Any], int]:
        return self._dump(ApiErrorResponse(error=error, message=message)), status

    def login(self, payload: Any) -> tuple[dict[str, Any], int]:
        if self._is_rate_limited("login"):
            return self._error("Too many login attempts. Please try again later.", 429)

        if payload.step == "password":
            return self._login_password(payload)
        if payload.step == "totp":
            return self._login_totp(payload)
        if payload.step == "security":
            return self._login_security(payload)
        return self._error(f"Unknown step: {payload.step}", 400)

    def _login_password(self, payload: Any) -> tuple[dict[str, Any], int]:
        username = payload.username
        password = payload.password
        if username is None or password is None:
            return self._error("Missing credentials", 400)

        db = self._get_db()
        user = db.execute("SELECT * FROM auth_users WHERE username = ?", (username,)).fetchone()

        if not user or not self._verify_and_upgrade(db, user["id"], "password", user["password"], password):
            self._record_failed_attempt("login")
            return self._error("Invalid credentials", 401)

        self.session["pending_user_id"] = user["id"]
        self.session["pending_username"] = user["username"]
        self.session["pending_role"] = user["role"]
        self.session["pending_totp_enabled"] = user["totp_enabled"]
        self.session["auth_step"] = "password_verified"

        if user["totp_enabled"]:
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

        if user["security_question"]:
            return (
                self._dump(
                    LoginStepResponse(
                        success=True,
                        next_step="security",
                        security_question=user["security_question"],
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
                    user=AuthenticatedUser(id=user["id"], username=user["username"], role=user["role"]),
                )
            ),
            200,
        )

    def _login_totp(self, payload: Any) -> tuple[dict[str, Any], int]:
        if "pending_user_id" not in self.session or self.session.get("auth_step") != "password_verified":
            return self._error("Invalid session state. Start from login.", 400)

        totp_code = payload.totp_code or ""
        if not totp_code or not totp_code.isdigit() or len(totp_code) != 6:
            self._record_failed_attempt("login")
            return self._error("Invalid 2FA code format. Code must be exactly 6 digits.", 400)

        db = self._get_db()
        user = db.execute(
            "SELECT totp_secret, security_question FROM auth_users WHERE id = ?",
            (self.session.get("pending_user_id"),),
        ).fetchone()
        if not user:
            return self._error("Invalid session state. Start from login.", 400)

        if not self._verify_totp(user["totp_secret"], totp_code):
            self._record_failed_attempt("login")
            return self._error("Invalid 2FA code", 401)

        self.session["auth_step"] = "totp_verified"

        if user["security_question"]:
            return (
                self._dump(
                    LoginStepResponse(
                        success=True,
                        next_step="security",
                        security_question=user["security_question"],
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

    def _login_security(self, payload: Any) -> tuple[dict[str, Any], int]:
        expected_step = "totp_verified" if self.session.get("pending_totp_enabled") else "password_verified"
        if "pending_user_id" not in self.session or self.session.get("auth_step") != expected_step:
            return self._error("Invalid session state. Start from login.", 400)

        answer = (payload.security_answer or "").lower()
        db = self._get_db()
        user = db.execute(
            "SELECT security_answer FROM auth_users WHERE id = ?",
            (self.session.get("pending_user_id"),),
        ).fetchone()
        if not user:
            return self._error("Invalid session state. Start from login.", 400)

        expected = user["security_answer"] or ""
        pending_user_id = self.session.get("pending_user_id")
        if pending_user_id is None:
            return self._error("Invalid session state. Start from login.", 400)

        if not self._verify_and_upgrade(db, int(pending_user_id), "security_answer", expected, answer):
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

        db = self._get_db()
        summaries: list[Any] = []
        for table_name in self._db_list_tables(db):
            count = db.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
            columns = self._db_table_columns(db, table_name)
            summaries.append(TableSummary(name=table_name, row_count=int(count), columns=columns))

        return self._dump(TablesResponse(tables=summaries)), 200

    def query(self, payload: Any) -> tuple[dict[str, Any], int]:
        if not self._enable_query_console:
            return self._error("Query console disabled", 403)

        db = self._get_db()
        query = payload.query
        query_lower = query.lower()
        allowed_prefixes = ("select", "pragma") if db.backend == "sqlite" else ("select", "show")
        if not query_lower.startswith(allowed_prefixes):
            return self._error(f"Only {', '.join(allowed_prefixes).upper()} queries are allowed", 403)
        if "auth_users" in query_lower:
            return self._error("Access denied to this table", 403)

        try:
            cursor = db.execute(query)
            columns = [description[0] for description in cursor.description] if cursor.description else []
            rows = cursor.fetchall()
            self._log_action("query", query=query)
            return (
                self._dump(
                    QuerySuccessResponse(
                        success=True,
                        columns=columns,
                        data=[dict(row) for row in rows],
                        row_count=len(rows),
                    )
                ),
                200,
            )
        except Exception as exc:  # pragma: no cover - exercised indirectly with DB driver specifics
            return self._error(str(exc), 400)

    def table_data(self, table_name: str, limit: int, offset: int) -> tuple[dict[str, Any], int]:
        if not self._enable_query_console:
            return self._error("Query console disabled", 403)
        if table_name == "auth_users":
            return self._error("Access denied", 403)

        try:
            db = self._get_db()
            if table_name not in self._db_list_tables(db):
                return self._error("Table not found", 404)

            total = db.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
            rows = db.execute(f"SELECT * FROM {table_name} LIMIT ? OFFSET ?", (limit, offset)).fetchall()
            self._log_action("view_table", table_name=table_name)
            return (
                self._dump(
                    TableDataResponse(
                        success=True,
                        table=table_name,
                        data=[dict(row) for row in rows],
                        total=int(total),
                        limit=limit,
                        offset=offset,
                    )
                ),
                200,
            )
        except Exception as exc:  # pragma: no cover - exercised indirectly with DB driver specifics
            return self._error(str(exc), 400)

    @staticmethod
    def audit_verify(valid: bool, info: dict[str, Any] | None) -> dict[str, Any]:
        return AuditVerifyResponse(valid=valid, info=info).model_dump(mode="json")
