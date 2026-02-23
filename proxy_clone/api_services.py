from __future__ import annotations

from typing import Any

from .api_schemas import ApiErrorResponse, ConnectApiRequest, HealthResponse, PublicStatusResponse, VaultStatusResponse


class ProxyApiService:
    """Encapsulates proxy-owned JSON API business logic."""

    def __init__(self, *, vault: Any, demo_mode: bool):
        self.vault = vault
        self.demo_mode = demo_mode

    @staticmethod
    def dump_model(model: Any) -> dict[str, Any]:
        return model.model_dump(mode="json")

    def error_response(self, error: str, status: int) -> tuple[dict[str, Any], int]:
        return self.dump_model(ApiErrorResponse(error=error)), status

    def vault_status(self) -> dict[str, Any]:
        status_payload = VaultStatusResponse(**self.vault.get_status())
        return status_payload.model_dump(mode="json")

    def require_stored_credentials(self) -> tuple[dict[str, Any], int] | None:
        if self.vault.credentials:
            return None
        return self.error_response("No stored credentials. Start with password step.", 400)

    def connect_password_step(self, payload: ConnectApiRequest) -> tuple[dict[str, Any], int] | dict[str, Any]:
        username = payload.username
        password = payload.password
        if username is None or password is None:
            return self.error_response("Missing credentials", 400)

        self.vault.store_credentials(username, password)
        return self.vault.login()

    def connect_totp_step(self, payload: ConnectApiRequest) -> tuple[dict[str, Any], int] | dict[str, Any]:
        missing = self.require_stored_credentials()
        if missing is not None:
            return missing
        return self.vault.login(totp_code=payload.totp_code or "")

    def connect_security_step(self, payload: ConnectApiRequest) -> tuple[dict[str, Any], int] | dict[str, Any]:
        missing = self.require_stored_credentials()
        if missing is not None:
            return missing
        return self.vault.login(security_answer=payload.security_answer or "")

    def format_connect_result(self, result: dict[str, Any]) -> tuple[dict[str, Any], int]:
        if result.get("success"):
            return {"success": True, "status": self.vault_status()}, 200

        if result.get("requires_totp") or result.get("requires_security"):
            pending_payload = dict(result)
            pending_payload["status"] = self.vault_status()
            return pending_payload, 200

        return self.error_response(str(result.get("error", "Failed to authenticate")), 401)

    def health(self) -> dict[str, Any]:
        return self.dump_model(HealthResponse(status="ok", demo_mode=self.demo_mode))

    def status(self) -> dict[str, Any]:
        return self.dump_model(PublicStatusResponse(**self.vault.get_public_status()))

    def connect(self, payload: ConnectApiRequest) -> tuple[dict[str, Any], int]:
        step_handlers = {
            "password": self.connect_password_step,
            "totp": self.connect_totp_step,
            "security": self.connect_security_step,
        }
        handler = step_handlers.get(payload.step)
        if handler is None:
            return self.error_response(f"Unknown step: {payload.step}", 400)

        step_result = handler(payload)
        if isinstance(step_result, tuple):
            return step_result
        return self.format_connect_result(step_result)
