from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for


class ProxyWebController:
    def __init__(
        self,
        *,
        vault: Any,
        drop_current_vault: Callable[[], None],
        debug: Callable[..., None],
        proxy_features_enabled: bool,
    ) -> None:
        self.vault = vault
        self.drop_current_vault = drop_current_vault
        self.debug = debug
        self.proxy_features_enabled = proxy_features_enabled

    def home(self):
        """Proxy's home page - query interface for end users."""
        if not self.proxy_features_enabled:
            return jsonify({"error": "Proxy demo features are disabled in production"}), 404
        status = self.vault.get_status()
        return render_template("home.html", status=status)

    def connect(self):
        """Page to capture/enter credentials - handles multi-step auth."""
        step = self.read_connect_step()
        self.log_connect_state(step)

        redirect_response = self.guard_connect_step(step)
        if redirect_response is not None:
            return redirect_response

        error = None
        if request.method == "POST":
            error, redirect_response = self.handle_connect_post(step)
            if redirect_response is not None:
                return redirect_response

        return self.render_connect(step=step, error=error)

    def read_connect_step(self) -> str:
        raw_step = request.args.get("step", "credentials") if request.method == "GET" else request.form.get(
            "step", "credentials"
        )
        valid_steps = {"credentials", "totp", "security"}
        if raw_step not in valid_steps:
            return "credentials"
        return str(raw_step)

    def log_connect_state(self, step: str) -> None:
        self.debug("connect() called - method=%s, step=%s", request.method, step)
        self.debug("vault.auth_state = %s", self.vault.auth_state)
        self.debug("vault.credentials = %s", bool(self.vault.credentials))

    def guard_connect_step(self, step: str):
        if step in {"totp", "security"} and not self.vault.credentials:
            return self.redirect_connect_step("credentials")
        return None

    def handle_connect_post(self, step: str) -> tuple[str | None, Any | None]:
        handlers: dict[str, Callable[[], tuple[str | None, Any | None]]] = {
            "credentials": self.handle_credentials_submit,
            "totp": self.handle_totp_submit,
            "security": self.handle_security_submit,
        }
        handler = handlers.get(step)
        if handler is None:
            return None, None
        return handler()

    def handle_credentials_submit(self) -> tuple[str | None, Any | None]:
        username = request.form.get("username")
        password = request.form.get("password")
        self.vault.store_credentials(username, password)
        self.vault.auth_state = {}

        result = self.vault.login()
        self.debug("credentials login result: %s", result)
        return self.resolve_connect_result(
            result,
            default_error="Failed to connect",
            allow_totp_redirect=True,
            allow_security_redirect=True,
            log_totp_redirect=True,
        )

    def handle_totp_submit(self) -> tuple[str | None, Any | None]:
        totp_code = request.form.get("totp_code", "").strip()
        self.debug("totp step - totp_code=%s, auth_state=%s", totp_code, self.vault.auth_state)

        if not totp_code:
            return "Please enter the 2FA code", None
        if not totp_code.isdigit() or len(totp_code) != 6:
            return "2FA code must be exactly 6 digits", None

        result = self.vault.login(totp_code=totp_code)
        self.debug("totp login result: %s", result)
        return self.resolve_connect_result(
            result,
            default_error="Invalid 2FA code",
            allow_totp_redirect=False,
            allow_security_redirect=True,
        )

    def handle_security_submit(self) -> tuple[str | None, Any | None]:
        security_answer = request.form.get("security_answer", "").strip()
        if not security_answer:
            return "Please enter your security answer", None

        result = self.vault.login(security_answer=security_answer)
        self.debug("security login result: %s", result)
        return self.resolve_connect_result(
            result,
            default_error="Invalid security answer",
            allow_totp_redirect=False,
            allow_security_redirect=False,
        )

    def resolve_connect_result(
        self,
        result: dict[str, Any],
        *,
        default_error: str,
        allow_totp_redirect: bool,
        allow_security_redirect: bool,
        log_totp_redirect: bool = False,
    ) -> tuple[str | None, Any | None]:
        if result.get("success"):
            return None, redirect(url_for("home"))

        if allow_totp_redirect and result.get("requires_totp"):
            if log_totp_redirect:
                self.debug("Redirecting to totp step, auth_state = %s", self.vault.auth_state)
            return None, self.redirect_connect_step("totp")

        if allow_security_redirect and result.get("requires_security"):
            session["security_question"] = result.get("security_question")
            return None, self.redirect_connect_step("security")

        return str(result.get("error", default_error)), None

    def redirect_connect_step(self, step: str):
        return redirect(url_for("connect", step=step))

    def render_connect(self, *, step: str, error: str | None):
        security_question = session.get("security_question") or self.vault.auth_state.get("security_question")
        return render_template(
            "connect.html",
            error=error,
            status=self.vault.get_status(),
            step=step,
            security_question=security_question,
        )

    def disconnect(self):
        """Clear stored credentials and all captured auth info."""
        self.vault.reset_auth(clear_credentials=True)
        self.drop_current_vault()
        session.pop("security_question", None)
        return redirect(url_for("connect"))

    def mirror(self, path: str = ""):
        """Mirror the original database server UI dynamically."""
        response = self.vault.proxy_request("GET", f"/{path}")
        if response is None:
            return "Failed to connect to database server", 503

        content = response.content
        content_type = response.headers.get("Content-Type", "text/html")

        if "text/html" in content_type:
            content = content.decode("utf-8")
            banner = """
        <div style="position:fixed;top:0;left:0;right:0;background:linear-gradient(90deg,#dc3545,#c82333);
                    color:white;text-align:center;padding:8px;z-index:9999;font-size:14px;">
            <i class="bi bi-shield-exclamation"></i>
            <strong>PROXY MIRROR</strong> - You are viewing through the proxy gateway
            <a href="/" style="color:white;margin-left:20px;">← Back to Proxy Home</a>
        </div>
        <style>body{margin-top:40px !important;}.sidebar{top:40px !important;height:calc(100vh - 40px) !important;}</style>
        """
            content = content.replace("<body>", f"<body>{banner}")
            content = content.replace('href="/', 'href="/mirror/')
            content = content.replace("href='/", "href='/mirror/")
            content = content.replace('action="/', 'action="/mirror/')
            content = content.encode("utf-8")

        return Response(content, content_type=content_type, status=response.status_code)

    def mirror_api(self, path: str):
        """Mirror API calls to the database server."""
        if request.method == "POST":
            response = self.vault.proxy_request("POST", f"/api/{path}", json=request.get_json())
        else:
            response = self.vault.proxy_request("GET", f"/api/{path}")

        if response is None:
            return jsonify({"error": "Failed to connect to database server"}), 503

        return Response(
            response.content,
            content_type=response.headers.get("Content-Type"),
            status=response.status_code,
        )


@dataclass(frozen=True)
class ProxyWebRouteDependencies:
    vault: Any
    feature_enabled: Callable[[Any], Any]
    proxy_authenticated: Callable[[Any], Any]
    drop_current_vault: Callable[[], None]
    debug: Callable[..., None]
    proxy_features_enabled: bool


def register_web_routes(app: Flask, deps: ProxyWebRouteDependencies) -> None:
    controller = ProxyWebController(
        vault=deps.vault,
        drop_current_vault=deps.drop_current_vault,
        debug=deps.debug,
        proxy_features_enabled=deps.proxy_features_enabled,
    )
    feature_enabled = deps.feature_enabled
    proxy_authenticated = deps.proxy_authenticated

    app.add_url_rule("/", endpoint="home", view_func=controller.home)
    app.add_url_rule(
        "/connect",
        endpoint="connect",
        view_func=feature_enabled(controller.connect),
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/disconnect",
        endpoint="disconnect",
        view_func=feature_enabled(controller.disconnect),
        methods=["POST"],
    )

    mirror_view = feature_enabled(proxy_authenticated(controller.mirror))
    app.add_url_rule("/mirror/", endpoint="mirror", view_func=mirror_view, defaults={"path": ""})
    app.add_url_rule("/mirror/<path:path>", endpoint="mirror", view_func=mirror_view)

    mirror_api_view = feature_enabled(proxy_authenticated(controller.mirror_api))
    app.add_url_rule(
        "/mirror/api/<path:path>",
        endpoint="mirror_api",
        view_func=mirror_api_view,
        methods=["GET", "POST"],
    )
