"""HTML web routes for proxy_clone."""

from .auth_guards import ProxyAuthGuards, pending_connect_step
from .routes import ProxyWebController, ProxyWebRouteDependencies, register_web_routes

__all__ = [
    "ProxyAuthGuards",
    "ProxyWebController",
    "ProxyWebRouteDependencies",
    "pending_connect_step",
    "register_web_routes",
]
