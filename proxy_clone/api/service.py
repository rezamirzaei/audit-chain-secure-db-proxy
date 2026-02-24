from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .schemas import ApiErrorResponse, ConnectApiRequest, HealthResponse, PublicStatusResponse, VaultStatusResponse
from ..state.protocols import ProxyVaultLike

JsonBody = dict[str, Any]
JsonResponse = tuple[JsonBody, int]
ConnectStepHandler = Callable[[ConnectApiRequest], JsonResponse]


class ProxyApiService:
    """Encapsulates proxy-owned JSON API business logic."""

    def __init__(self, *, vault: ProxyVaultLike, demo_mode: bool):
        self.vault = vault
        self.demo_mode = demo_mode
        self._connect_step_handlers: dict[str, ConnectStepHandler] = {
            "password": self.connect_password_step,
            "totp": self.connect_totp_step,
            "security": self.connect_security_step,
        }

    @staticmethod
    def dump_model(model: Any) -> JsonBody:
        return model.model_dump(mode="json")

    def error_response(self, error: str, status: int) -> JsonResponse:
        return self.dump_model(ApiErrorResponse(error=error)), status

    def vault_status(self) -> JsonBody:
        return VaultStatusResponse(**self.vault.get_status()).model_dump(mode="json")

    def require_stored_credentials(self) -> JsonResponse | None:
        if self.vault.credentials:
            return None
        return self.error_response("No stored credentials. Start with password step.", 400)

    def format_connect_result(self, result: JsonBody) -> JsonResponse:
        if result.get("success"):
            return {"success": True, "status": self.vault_status()}, 200

        if result.get("requires_totp") or result.get("requires_security"):
            pending_payload = dict(result)
            pending_payload["status"] = self.vault_status()
            return pending_payload, 200

        return self.error_response(str(result.get("error", "Failed to authenticate")), 401)

    def connect_password_step(self, payload: ConnectApiRequest) -> JsonResponse:
        username = payload.username
        password = payload.password
        if username is None or password is None:
            return self.error_response("Missing credentials", 400)

        self.vault.store_credentials(username, password)
        return self.format_connect_result(self.vault.login())

    def connect_totp_step(self, payload: ConnectApiRequest) -> JsonResponse:
        missing = self.require_stored_credentials()
        if missing is not None:
            return missing
        return self.format_connect_result(self.vault.login(totp_code=payload.totp_code or ""))

    def connect_security_step(self, payload: ConnectApiRequest) -> JsonResponse:
        missing = self.require_stored_credentials()
        if missing is not None:
            return missing
        return self.format_connect_result(self.vault.login(security_answer=payload.security_answer or ""))

    def health(self) -> JsonBody:
        return self.dump_model(HealthResponse(status="ok", demo_mode=self.demo_mode))

    def status(self) -> JsonBody:
        return self.dump_model(PublicStatusResponse(**self.vault.get_public_status()))

    def connect(self, payload: ConnectApiRequest) -> JsonResponse:
        handler = self._connect_step_handlers.get(payload.step)
        if handler is None:
            return self.error_response(f"Unknown step: {payload.step}", 400)
        return handler(payload)
