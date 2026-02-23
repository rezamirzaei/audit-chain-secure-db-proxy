from __future__ import annotations

from typing import TypeVar

from flask import Request
from pydantic import BaseModel, ValidationError

TModel = TypeVar("TModel", bound=BaseModel)


class RequestPayloadValidationError(Exception):
    """Raised when a JSON request body fails schema validation."""

    def __init__(self, errors: list[dict[str, object]]):
        super().__init__("Invalid request payload")
        self.errors = errors


class RequestValidator:
    """Pydantic-backed JSON payload parser for Flask request handlers."""

    @staticmethod
    def parse_json(request: Request, model_cls: type[TModel]) -> TModel:
        payload = request.get_json(silent=True)
        if payload is None:
            raise RequestPayloadValidationError(
                [{"loc": ["body"], "msg": "JSON body required", "type": "missing"}]
            )
        try:
            return model_cls.model_validate(payload)
        except ValidationError as exc:
            errors = [dict(error) for error in exc.errors(include_url=False, include_context=False)]
            raise RequestPayloadValidationError(errors) from exc
