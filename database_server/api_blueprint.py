"""Compatibility wrapper for `database_server.api.blueprint`."""

from __future__ import annotations

from .api.blueprint import DatabaseApiBlueprintDependencies as DatabaseApiBlueprintDependencies
from .api.blueprint import DatabaseApiController as DatabaseApiController
from .api.blueprint import create_api_blueprint as create_api_blueprint

__all__ = [
    "DatabaseApiBlueprintDependencies",
    "DatabaseApiController",
    "create_api_blueprint",
]

