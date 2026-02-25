from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

import requests

JsonDict = dict[str, Any]


class ResponseLike(Protocol):
    status_code: int

    def json(self) -> object: ...


class SessionLike(Protocol):
    verify: bool
    cookies: Any

    def request(self, method: str, url: str, timeout: int, **kwargs: Any) -> requests.Response: ...


def default_session_factory() -> SessionLike:
    # `requests.Session` satisfies `SessionLike`, but requests' types don't declare it.
    return cast(SessionLike, requests.Session())


@dataclass
class UpstreamClient:
    base_url: str
    ssl_verify: bool
    session_factory: Callable[[], SessionLike] = default_session_factory
    session: SessionLike = field(init=False)

    def __post_init__(self) -> None:
        self.new_session()

    def new_session(self) -> None:
        self.session = self.session_factory()
        self.session.verify = self.ssl_verify

    def url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def request(self, method: str, path: str, *, timeout: int, **kwargs: Any) -> requests.Response:
        return self.session.request(method, self.url(path), timeout=timeout, **kwargs)

    def post_json(self, path: str, payload: JsonDict, *, timeout: int) -> tuple[requests.Response, JsonDict]:
        response = self.request("POST", path, timeout=timeout, json=payload)
        return response, self.response_json(response)

    def get_json(self, path: str, *, timeout: int) -> tuple[requests.Response, JsonDict]:
        response = self.request("GET", path, timeout=timeout)
        return response, self.response_json(response)

    @staticmethod
    def response_json(response: ResponseLike) -> JsonDict:
        try:
            payload = response.json()
        except ValueError:
            return {"error": "Upstream returned an invalid JSON response"}
        if isinstance(payload, dict):
            return payload
        return {"error": "Upstream returned an unexpected response payload"}
