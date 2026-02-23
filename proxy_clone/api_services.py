from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any


def _load_sibling_module(module_name: str):
    if __package__:
        return importlib.import_module(f"{__package__}.{module_name}")

    module_path = Path(__file__).with_name(f"{module_name}.py")
    import_name = f"{Path(__file__).parent.name}_{module_name}"
    spec = importlib.util.spec_from_file_location(import_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[import_name] = module
    spec.loader.exec_module(module)
    return module


_api_schemas_module = _load_sibling_module("api_schemas")
ApiErrorResponse = _api_schemas_module.ApiErrorResponse
ConnectApiRequest = _api_schemas_module.ConnectApiRequest
HealthResponse = _api_schemas_module.HealthResponse
PublicStatusResponse = _api_schemas_module.PublicStatusResponse
VaultStatusResponse = _api_schemas_module.VaultStatusResponse


class ProxyApiService:
    """Encapsulates proxy-owned JSON API business logic."""

    def __init__(self, *, vault: Any, demo_mode: bool):
        self.vault = vault
        self.demo_mode = demo_mode

    @staticmethod
    def _dump(model: Any) -> dict[str, Any]:
        return model.model_dump(mode="json")

    def _error(self, error: str, status: int) -> tuple[dict[str, Any], int]:
        return self._dump(ApiErrorResponse(error=error)), status

    def health(self) -> dict[str, Any]:
        return self._dump(HealthResponse(status="ok", demo_mode=self.demo_mode))

    def status(self) -> dict[str, Any]:
        return self._dump(PublicStatusResponse(**self.vault.get_public_status()))

    def connect(self, payload: Any) -> tuple[dict[str, Any], int]:
        if payload.step == "password":
            username = payload.username
            password = payload.password
            if username is None or password is None:
                return self._error("Missing credentials", 400)

            self.vault.store_credentials(username, password)
            result = self.vault.login()

        elif payload.step == "totp":
            if not self.vault.credentials:
                return self._error("No stored credentials. Start with password step.", 400)
            result = self.vault.login(totp_code=payload.totp_code or "")

        elif payload.step == "security":
            if not self.vault.credentials:
                return self._error("No stored credentials. Start with password step.", 400)
            result = self.vault.login(security_answer=payload.security_answer or "")

        else:
            return self._error(f"Unknown step: {payload.step}", 400)

        if result.get("success"):
            status_payload = VaultStatusResponse(**self.vault.get_status())
            return {"success": True, "status": status_payload.model_dump(mode="json")}, 200

        if result.get("requires_totp") or result.get("requires_security"):
            pending_payload = dict(result)
            pending_payload["status"] = VaultStatusResponse(**self.vault.get_status()).model_dump(mode="json")
            return pending_payload, 200

        return self._error(str(result.get("error", "Failed to authenticate")), 401)
