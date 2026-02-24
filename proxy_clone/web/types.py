from __future__ import annotations

from typing import Any, Protocol


class ProxyVaultLike(Protocol):
    """Minimal protocol the proxy web layer needs from a credential vault."""

    credentials: dict[str, Any]
    auth_state: dict[str, Any]

    def get_status(self) -> dict[str, Any]: ...

    def store_credentials(self, username: Any, password: Any) -> None: ...

    def login(
        self,
        totp_code: str | None = None,
        security_answer: str | None = None,
    ) -> dict[str, Any]: ...

    def reset_auth(self, clear_credentials: bool = False) -> None: ...

    def proxy_request(self, method: str, path: str, **kwargs: Any) -> Any | None: ...

