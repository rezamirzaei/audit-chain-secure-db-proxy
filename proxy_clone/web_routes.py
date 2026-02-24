"""Compatibility wrapper for `proxy_clone.web.routes`."""

from __future__ import annotations

from .web.routes import (
    PROXY_MIRROR_BANNER_HTML as PROXY_MIRROR_BANNER_HTML,
    ProxyWebController as ProxyWebController,
    ProxyWebRouteDependencies as ProxyWebRouteDependencies,
    register_web_routes as register_web_routes,
)

__all__ = [
    "PROXY_MIRROR_BANNER_HTML",
    "ProxyWebController",
    "ProxyWebRouteDependencies",
    "register_web_routes",
]

