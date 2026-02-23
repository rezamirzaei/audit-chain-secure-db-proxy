from __future__ import annotations

import secrets
import threading
from collections.abc import Callable
from typing import Any

from .credential_vault import CredentialVault


class VaultRegistry:
    def __init__(self, factory: Callable[[], CredentialVault]) -> None:
        self._factory = factory
        self._vaults: dict[str, CredentialVault] = {}
        self._lock = threading.Lock()

    @property
    def vaults(self) -> dict[str, CredentialVault]:
        return self._vaults

    def current(self, session_store: Any) -> CredentialVault:
        vault_id = session_store.get("vault_id")
        if not vault_id:
            vault_id = secrets.token_urlsafe(16)
            session_store["vault_id"] = vault_id

        with self._lock:
            instance = self._vaults.get(vault_id)
            if instance is None:
                instance = self._factory()
                self._vaults[vault_id] = instance
            return instance

    def drop_current(self, session_store: Any) -> None:
        vault_id = session_store.pop("vault_id", None)
        if not vault_id:
            return
        with self._lock:
            self._vaults.pop(vault_id, None)

