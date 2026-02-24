from __future__ import annotations

from collections.abc import Callable
from typing import Any

import requests

from .upstream_client import UpstreamClient
from .vault_types import CredentialVaultConfig, CredentialVaultState


class VaultProxyEngine:
    """Ensures an upstream session exists and proxies upstream requests."""

    def __init__(
        self,
        *,
        client: UpstreamClient,
        config: CredentialVaultConfig,
        state: CredentialVaultState,
        login_fn: Callable[..., dict[str, Any]],
    ) -> None:
        self._client = client
        self._config = config
        self._state = state
        self._login = login_fn

    def upstream_session_authenticated(self) -> bool:
        response, data = self._client.get_json(
            self._config.upstream_session_path,
            timeout=self._config.session_check_timeout_seconds,
        )
        if response.status_code != 200:
            return False
        return bool(data.get("authenticated"))

    def reauthenticate(self) -> bool:
        result = self._login(security_answer=self._state.security_info.get("answer"))
        return bool(result.get("success", False))

    def ensure_session(self) -> bool:
        if not self._state.credentials:
            return False

        try:
            if self.upstream_session_authenticated():
                return True
        except Exception:
            pass

        return self.reauthenticate()

    def request_upstream(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        return self._client.request(method, path, timeout=self._config.proxy_request_timeout_seconds, **kwargs)

    def proxy_request(self, method: str, path: str, **kwargs: Any) -> Any | None:
        if not self.ensure_session():
            return None

        try:
            return self.request_upstream(method, path, **kwargs)
        except Exception:
            return None

