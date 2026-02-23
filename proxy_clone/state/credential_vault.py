from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

import requests


class CredentialVault:
    """
    Stores captured credentials, auth factors, and upstream session cookies.
    Handles the multi-step authentication flow to the database server.
    """

    def __init__(
        self,
        *,
        database_server_url: str,
        ssl_verify: bool,
        debug_log: Callable[..., None] | None = None,
    ) -> None:
        self._database_server_url = database_server_url
        self._ssl_verify = ssl_verify
        self._debug_log = debug_log

        self.credentials: dict[str, Any] = {}
        self.totp_info: dict[str, Any] = {}
        self.security_info: dict[str, Any] = {}
        self.session_cookies: dict[str, Any] = {}
        self.active_session: bool | None = None
        self.last_login: datetime | None = None
        self.auto_refresh_running = False
        self.auth_state: dict[str, Any] = {}
        self._new_session()

    def _debug(self, msg: str, *args: Any) -> None:
        if self._debug_log is not None:
            self._debug_log(msg, *args)

    def _new_session(self) -> None:
        self._requests_session = requests.Session()
        self._requests_session.verify = self._ssl_verify

    def reset_auth(self, clear_credentials: bool = False) -> None:
        if clear_credentials:
            self.credentials = {}
        self.totp_info = {}
        self.security_info = {}
        self.session_cookies = {}
        self.active_session = None
        self.auth_state = {}
        self.last_login = None
        self._new_session()

    def store_credentials(self, username: Any, password: Any) -> None:
        self.reset_auth(clear_credentials=False)
        self.credentials = {
            "username": username,
            "password": password,
            "captured_at": datetime.now().isoformat(),
        }

    def store_totp_code(self, totp_code: Any) -> None:
        self.totp_info = {
            "last_code": totp_code,
            "captured_at": datetime.now().isoformat(),
        }

    def store_security_answer(self, question: Any, answer: Any) -> None:
        self.security_info = {
            "question": question,
            "answer": answer,
            "captured_at": datetime.now().isoformat(),
        }

    def store_cookies(self, cookies: Any) -> None:
        self.session_cookies = dict(cookies)
        self.last_login = datetime.now()

    def get_session(self) -> requests.Session:
        return self._requests_session

    def multi_step_login(self, totp_code: str | None = None, security_answer: str | None = None) -> dict[str, Any]:
        self._debug(
            "multi_step_login called - totp_code=%s, security_answer=%s",
            bool(totp_code),
            bool(security_answer),
        )
        self._debug("current auth_state = %s", self.auth_state)

        if not self.credentials:
            return {"success": False, "error": "No credentials stored"}

        try:
            current_step = self.auth_state.get("current_step", "password")
            self._debug("current_step = %s", current_step)

            if totp_code and current_step != "waiting_security":
                self._debug("Sending TOTP code to server...")
                self.store_totp_code(totp_code)
                response = self._requests_session.post(
                    f"{self._database_server_url}/api/login",
                    json={"step": "totp", "totp_code": totp_code},
                    timeout=10,
                )
                data = response.json()

                if response.status_code != 200:
                    if "Invalid session state" in data.get("error", ""):
                        self.auth_state = {"current_step": "password"}
                    return {"success": False, "error": data.get("error", "2FA verification failed")}

                if data.get("next_step") == "security":
                    question = data.get("security_question")
                    self.auth_state["current_step"] = "waiting_security"
                    self.auth_state["security_question"] = question
                    return {
                        "success": False,
                        "error": "Security question verification required",
                        "requires_security": True,
                        "security_question": question,
                        "message": "Please answer your security question",
                        "state": data,
                    }
                if data.get("authenticated"):
                    self.store_cookies(self._requests_session.cookies)
                    self.active_session = True
                    self.auth_state = {"authenticated": True, "user": data.get("user")}
                    return {"success": True, "data": data}
                return {"success": False, "error": "Authentication failed after 2FA"}

            if security_answer and current_step == "waiting_security":
                question = self.auth_state.get("security_question", "")
                self.store_security_answer(question, security_answer)
                response = self._requests_session.post(
                    f"{self._database_server_url}/api/login",
                    json={"step": "security", "security_answer": security_answer},
                    timeout=10,
                )
                data = response.json()

                if response.status_code != 200:
                    return {"success": False, "error": data.get("error", "Security verification failed")}

                if data.get("authenticated"):
                    self.store_cookies(self._requests_session.cookies)
                    self.active_session = True
                    self.auth_state = {"authenticated": True, "user": data.get("user")}
                    return {"success": True, "data": data}
                return {"success": False, "error": "Authentication failed after security question"}

            self.auth_state = {"current_step": "password"}
            response = self._requests_session.post(
                f"{self._database_server_url}/api/login",
                json={
                    "step": "password",
                    "username": self.credentials["username"],
                    "password": self.credentials["password"],
                },
                timeout=10,
            )
            data = response.json()

            if response.status_code != 200:
                return {"success": False, "error": data.get("error", "Password verification failed")}

            if data.get("next_step") == "totp":
                self.auth_state["current_step"] = "waiting_totp"
                return {
                    "success": False,
                    "error": "Two-factor authentication required",
                    "requires_totp": True,
                    "message": "Please enter your 2FA code from your authenticator app",
                    "state": data,
                }

            if data.get("next_step") == "security":
                question = data.get("security_question")
                self.auth_state["current_step"] = "waiting_security"
                self.auth_state["security_question"] = question
                return {
                    "success": False,
                    "error": "Security question verification required",
                    "requires_security": True,
                    "security_question": question,
                    "message": "Please answer your security question",
                    "state": data,
                }

            if data.get("authenticated"):
                self.store_cookies(self._requests_session.cookies)
                self.active_session = True
                self.auth_state = {"authenticated": True, "user": data.get("user")}
                return {"success": True, "data": data}

            return {"success": False, "error": "Authentication incomplete", "state": data}
        except Exception as exc:  # pragma: no cover - network/client failures
            return {"success": False, "error": str(exc)}

    def login(self, totp_code: str | None = None, security_answer: str | None = None) -> dict[str, Any]:
        return self.multi_step_login(totp_code, security_answer)

    def ensure_session(self) -> bool:
        if not self.credentials:
            return False

        try:
            response = self._requests_session.get(f"{self._database_server_url}/api/session", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("authenticated"):
                    return True
        except Exception:
            pass

        result = self.login(security_answer=self.security_info.get("answer"))
        return bool(result.get("success", False))

    def proxy_request(self, method: str, path: str, **kwargs: Any) -> Any | None:
        if not self.ensure_session():
            return None

        url = f"{self._database_server_url}{path}"
        try:
            if method == "GET":
                return self._requests_session.get(url, timeout=30, **kwargs)
            if method == "POST":
                return self._requests_session.post(url, timeout=30, **kwargs)
            return self._requests_session.request(method, url, timeout=30, **kwargs)
        except Exception:
            return None

    def get_status(self) -> dict[str, Any]:
        return {
            "has_credentials": bool(self.credentials),
            "username": self.credentials.get("username"),
            "captured_at": self.credentials.get("captured_at"),
            "has_totp": bool(self.totp_info),
            "has_security_answer": bool(self.security_info.get("answer")),
            "security_question": self.security_info.get("question"),
            "has_session": bool(self.session_cookies),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "active": self.active_session,
            "auth_state": self.auth_state,
        }

    def get_public_status(self) -> dict[str, Any]:
        return {
            "has_credentials": bool(self.credentials),
            "has_totp": bool(self.totp_info),
            "has_security_answer": bool(self.security_info.get("answer")),
            "has_session": bool(self.session_cookies),
            "active": bool(self.active_session),
        }

