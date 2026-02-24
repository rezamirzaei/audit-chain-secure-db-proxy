from __future__ import annotations

from typing import Any, Protocol


class ProxyVaultLike(Protocol):
    """Shared protocol for objects that behave like `CredentialVault`.

    The web layer, API layer, and auth guards each depend on different subsets
    of the vault interface. Keeping a superset here avoids repeating near-identical
    protocols across modules.
    """

    credentials: dict[str, Any]
    auth_state: dict[str, Any]

    def get_status(self) -> dict[str, Any]: ...

    def get_public_status(self) -> dict[str, Any]: ...

    def store_credentials(self, username: Any, password: Any) -> None: ...

    def login(
        self,
        totp_code: str | None = None,
        security_answer: str | None = None,
    ) -> dict[str, Any]: ...

    def reset_auth(self, clear_credentials: bool = False) -> None: ...

    def ensure_session(self) -> bool: ...

    def proxy_request(self, method: str, path: str, **kwargs: Any) -> Any | None: ...

