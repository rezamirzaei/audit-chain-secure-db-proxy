"""Compatibility wrapper for `proxy_clone.api.blueprint`."""

from __future__ import annotations

from .api.blueprint import ProxyApiBlueprintDependencies as ProxyApiBlueprintDependencies
from .api.blueprint import ProxyApiController as ProxyApiController
from .api.blueprint import create_api_blueprint as create_api_blueprint

__all__ = [
    "ProxyApiBlueprintDependencies",
    "ProxyApiController",
    "create_api_blueprint",
]

