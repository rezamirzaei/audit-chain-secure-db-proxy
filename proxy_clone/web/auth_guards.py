from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import wraps
from typing import Any, TypeVar, cast

from flask import jsonify, redirect, url_for

from .types import ProxyVaultLike

F = TypeVar("F", bound=Callable[..., Any])

WAITING_TOTP_STEP = "waiting_totp"
WAITING_SECURITY_STEP = "waiting_security"


def pending_connect_step(auth_state: Mapping[str, Any]) -> str | None:
    """Map upstream auth_state to the next `/connect?step=...` UI step."""
    step = auth_state.get("current_step")
    if step == WAITING_TOTP_STEP:
        return "totp"
    if step == WAITING_SECURITY_STEP:
        return "security"
    return None


@dataclass(frozen=True)
class ProxyAuthGuards:
    """Auth-related decorators for the proxy web server."""

    vault: ProxyVaultLike

    def redirect_for_pending_proxy_auth(self) -> str:
        step = pending_connect_step(self.vault.auth_state)
        if step is None:
            return url_for("connect")
        return url_for("connect", step=step)

    def proxy_authenticated(self, f: F) -> F:
        """Ensure the proxy has captured credentials and has an active upstream session."""

        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            if not self.vault.credentials:
                return redirect(url_for("connect"))
            if not self.vault.ensure_session():
                return redirect(self.redirect_for_pending_proxy_auth())
            return f(*args, **kwargs)

        return cast(F, decorated_function)

    def proxy_status_available(self, f: F) -> F:
        """Allow API status access after credentials have been captured."""

        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            if not self.vault.credentials:
                return jsonify({"error": "Not connected"}), 401
            return f(*args, **kwargs)

        return cast(F, decorated_function)
