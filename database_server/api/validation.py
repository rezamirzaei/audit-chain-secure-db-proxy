"""Compatibility wrapper around shared request validation helpers."""

from shared.request_validation import (
    RequestPayloadValidationError as RequestPayloadValidationError,
    RequestValidator as RequestValidator,
)

__all__ = ["RequestPayloadValidationError", "RequestValidator"]
