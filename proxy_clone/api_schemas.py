from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ConnectApiRequest(_StrictModel):
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
    def validate_step_payload(self) -> ConnectApiRequest:
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


class HealthResponse(_ResponseModel):
    status: Literal["ok"]
    demo_mode: bool


class PublicStatusResponse(_ResponseModel):
    has_credentials: bool
    has_totp: bool
    has_security_answer: bool
    has_session: bool
    active: bool


class VaultStatusResponse(_ResponseModel):
    has_credentials: bool
    username: str | None = None
    captured_at: str | None = None
    has_totp: bool
    has_security_answer: bool
    security_question: str | None = None
    has_session: bool
    last_login: str | None = None
    active: bool | None = None
    auth_state: dict[str, Any]


class TablePathParams(_ParamModel):
    table_name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
