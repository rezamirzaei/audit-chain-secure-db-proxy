from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Response, jsonify, request

from .types import ProxyVaultLike

PROXY_MIRROR_BANNER_HTML = """
        <div style="position:fixed;top:0;left:0;right:0;background:linear-gradient(90deg,#dc3545,#c82333);
                    color:white;text-align:center;padding:8px;z-index:9999;font-size:14px;">
            <i class="bi bi-shield-exclamation"></i>
            <strong>PROXY MIRROR</strong> - You are viewing through the proxy gateway
            <a href="/" style="color:white;margin-left:20px;">← Back to Proxy Home</a>
        </div>
        <style>
            body{margin-top:40px !important;}
            .sidebar{top:40px !important;height:calc(100vh - 40px) !important;}
        </style>
        """


def rewrite_mirrored_html(content: str) -> str:
    content = content.replace("<body>", f"<body>{PROXY_MIRROR_BANNER_HTML}")
    content = content.replace('href="/', 'href="/mirror/')
    content = content.replace("href='/", "href='/mirror/")
    content = content.replace('action="/', 'action="/mirror/')
    return content


def mirror_api_request_params() -> tuple[str, dict[str, Any]]:
    if request.method == "POST":
        return "POST", {"json": request.get_json()}
    return "GET", {}


class ProxyMirrorController:
    """Mirroring routes: proxy the upstream HTML UI and API responses."""

    def __init__(
        self,
        *,
        vault: ProxyVaultLike,
        debug: Callable[..., None],
    ) -> None:
        self.vault = vault
        self.debug = debug

    def mirror(self, path: str = ""):
        """Mirror the original database server UI dynamically."""
        response = self.vault.proxy_request("GET", f"/{path}")
        if response is None:
            return "Failed to connect to database server", 503

        content_type = response.headers.get("Content-Type", "text/html")
        content = self.mirror_response_content(response.content, content_type)
        return Response(content, content_type=content_type, status=response.status_code)

    def mirror_response_content(self, content: bytes, content_type: str) -> bytes:
        if "text/html" not in content_type:
            return content
        return rewrite_mirrored_html(content.decode("utf-8")).encode("utf-8")

    def mirror_api(self, path: str):
        """Mirror API calls to the database server."""
        method, kwargs = mirror_api_request_params()
        response = self.vault.proxy_request(method, f"/api/{path}", **kwargs)

        if response is None:
            return jsonify({"error": "Failed to connect to database server"}), 503

        return Response(
            response.content,
            content_type=response.headers.get("Content-Type"),
            status=response.status_code,
        )

