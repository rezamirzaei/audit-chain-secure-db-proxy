"""State and session-related components for proxy_clone."""

from .credential_vault import CredentialVault
from .protocols import ProxyVaultLike
from .upstream_client import JsonDict, UpstreamClient
from .vault_registry import VaultRegistry
from .vault_types import CredentialVaultConfig, CredentialVaultState

__all__ = [
    "CredentialVault",
    "CredentialVaultConfig",
    "CredentialVaultState",
    "JsonDict",
    "ProxyVaultLike",
    "UpstreamClient",
    "VaultRegistry",
]
