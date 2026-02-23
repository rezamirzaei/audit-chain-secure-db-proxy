from __future__ import annotations

from typing import Any

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for


def register_web_routes(app: Flask, deps: dict[str, Any]) -> None:
    vault = deps["vault"]
    feature_enabled = deps["feature_enabled"]
    proxy_authenticated = deps["proxy_authenticated"]
    drop_current_vault = deps["drop_current_vault"]
    debug = deps["debug"]
    proxy_features_enabled = deps["proxy_features_enabled"]

    @app.route("/")
    def home():
        """Proxy's home page - query interface for end users."""
        if not proxy_features_enabled:
            return jsonify({"error": "Proxy demo features are disabled in production"}), 404
        status = vault.get_status()
        return render_template("home.html", status=status)

    @app.route("/connect", methods=["GET", "POST"])
    @feature_enabled
    def connect():
        """Page to capture/enter credentials - handles multi-step auth."""
        error = None
        status = vault.get_status()

        if request.method == "GET":
            step = request.args.get("step", "credentials")
        else:
            step = request.form.get("step", "credentials")

        debug("connect() called - method=%s, step=%s", request.method, step)
        debug("vault.auth_state = %s", vault.auth_state)
        debug("vault.credentials = %s", bool(vault.credentials))

        if step in ["totp", "security"] and not vault.credentials:
            return redirect(url_for("connect", step="credentials"))

        if request.method == "POST":
            if step == "credentials":
                username = request.form.get("username")
                password = request.form.get("password")
                vault.store_credentials(username, password)
                vault.auth_state = {}
                result = vault.login()
                debug("credentials login result: %s", result)

                if result.get("success"):
                    return redirect(url_for("home"))
                if result.get("requires_totp"):
                    debug("Redirecting to totp step, auth_state = %s", vault.auth_state)
                    return redirect(url_for("connect", step="totp"))
                if result.get("requires_security"):
                    session["security_question"] = result.get("security_question")
                    return redirect(url_for("connect", step="security"))
                error = result.get("error", "Failed to connect")

            elif step == "totp":
                totp_code = request.form.get("totp_code", "").strip()
                debug("totp step - totp_code=%s, auth_state=%s", totp_code, vault.auth_state)

                if not totp_code:
                    error = "Please enter the 2FA code"
                elif not totp_code.isdigit() or len(totp_code) != 6:
                    error = "2FA code must be exactly 6 digits"
                else:
                    result = vault.login(totp_code=totp_code)
                    debug("totp login result: %s", result)

                    if result.get("success"):
                        return redirect(url_for("home"))
                    if result.get("requires_security"):
                        session["security_question"] = result.get("security_question")
                        return redirect(url_for("connect", step="security"))
                    error = result.get("error", "Invalid 2FA code")

            elif step == "security":
                security_answer = request.form.get("security_answer", "").strip()

                if not security_answer:
                    error = "Please enter your security answer"
                else:
                    result = vault.login(security_answer=security_answer)
                    debug("security login result: %s", result)

                    if result.get("success"):
                        return redirect(url_for("home"))
                    error = result.get("error", "Invalid security answer")

        security_question = session.get("security_question") or vault.auth_state.get("security_question")
        return render_template(
            "connect.html",
            error=error,
            status=status,
            step=step,
            security_question=security_question,
        )

    @app.route("/disconnect", methods=["POST"])
    @feature_enabled
    def disconnect():
        """Clear stored credentials and all captured auth info."""
        vault.reset_auth(clear_credentials=True)
        drop_current_vault()
        session.pop("security_question", None)
        return redirect(url_for("connect"))

    @app.route("/mirror/")
    @app.route("/mirror/<path:path>")
    @feature_enabled
    @proxy_authenticated
    def mirror(path: str = ""):
        """Mirror the original database server UI dynamically."""
        response = vault.proxy_request("GET", f"/{path}")
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

    @app.route("/mirror/api/<path:path>", methods=["GET", "POST"])
    @feature_enabled
    @proxy_authenticated
    def mirror_api(path: str):
        """Mirror API calls to the database server."""
        if request.method == "POST":
            response = vault.proxy_request("POST", f"/api/{path}", json=request.get_json())
        else:
            response = vault.proxy_request("GET", f"/api/{path}")

        if response is None:
            return jsonify({"error": "Failed to connect to database server"}), 503

        return Response(
            response.content,
            content_type=response.headers.get("Content-Type"),
            status=response.status_code,
        )

