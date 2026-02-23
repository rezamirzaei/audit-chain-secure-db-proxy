from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class LoginApiRequest(_StrictModel):
    step: Literal["password", "totp", "security"] = "password"
    username: str | None = None
    password: str | None = None
    totp_code: str | None = None
    security_answer: str | None = None

    @field_validator("username", "password", "totp_code", "security_answer", mode="before")
    @classmethod
    def strip_optional_strings(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip()
        return value

    @model_validator(mode="after")
    def validate_step_payload(self) -> LoginApiRequest:
        if self.step == "password":
            if not self.username or not self.password:
                raise ValueError("username and password are required for password step")
        elif self.step == "totp":
            if not self.totp_code:
                raise ValueError("totp_code is required for totp step")
            if not self.totp_code.isdigit() or len(self.totp_code) != 6:
                raise ValueError("totp_code must be exactly 6 digits")
        elif self.step == "security" and not self.security_answer:
            raise ValueError("security_answer is required for security step")
        return self


class QueryApiRequest(_StrictModel):
    query: str

    @field_validator("query", mode="before")
    @classmethod
    def strip_query(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("query")
    @classmethod
    def ensure_query_present(cls, value: str) -> str:
        if not value:
            raise ValueError("query must not be empty")
        return value


class _ResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _ParamModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=False)


class ApiErrorResponse(_ResponseModel):
    error: str
    message: str | None = None


class HealthResponse(_ResponseModel):
    status: Literal["healthy"]
    timestamp: str
    database: Literal["connected"]


class SessionResponse(_ResponseModel):
    authenticated: bool
    user_id: int | None = None
    username: str | None = None
    role: str | None = None
    login_time: str | None = None


class AuthenticatedUser(_ResponseModel):
    id: int
    username: str
    role: str


class LoginStepResponse(_ResponseModel):
    success: Literal[True]
    next_step: Literal["totp", "security"]
    message: str
    requires_2fa: bool | None = None
    security_question: str | None = None


class LoginSuccessResponse(_ResponseModel):
    success: Literal[True]
    authenticated: Literal[True]
    user: AuthenticatedUser


class TotpCurrentResponse(_ResponseModel):
    username: str
    totp_token: str
    valid_for_seconds: int


class LogoutResponse(_ResponseModel):
    success: Literal[True]


class TableSummary(_ResponseModel):
    name: str
    row_count: int
    columns: list[dict[str, str]]


class TablesResponse(_ResponseModel):
    tables: list[TableSummary]


class QuerySuccessResponse(_ResponseModel):
    success: Literal[True]
    columns: list[str]
    data: list[dict[str, Any]]
    row_count: int


class TableDataResponse(_ResponseModel):
    success: Literal[True]
    table: str
    data: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class AuditVerifyResponse(_ResponseModel):
    valid: bool
    info: dict[str, Any] | None


class TablePathParams(_ParamModel):
    table_name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")


class TablePaginationParams(_ParamModel):
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
