"""Shared SSL/HTTPS certificate lookup helpers."""

from __future__ import annotations

import os
from typing import Final

SslContextTuple = tuple[str | None, str | None]

DEFAULT_SSL_SEARCH_PATHS: Final[tuple[tuple[str, str], ...]] = (
    ("/app/certs/cert.pem", "/app/certs/key.pem"),
    ("certs/cert.pem", "certs/key.pem"),
)


class SSLConfig:
    """Manage SSL certificate discovery across common runtime layouts."""

    SSL_SEARCH_PATHS = list(DEFAULT_SSL_SEARCH_PATHS)

    @classmethod
    def find_certificates(cls) -> SslContextTuple:
        for cert_path, key_path in cls.SSL_SEARCH_PATHS:
            if os.path.exists(cert_path) and os.path.exists(key_path):
                return cert_path, key_path
        return None, None

    @classmethod
    def has_certificates(cls) -> bool:
        cert_path, key_path = cls.find_certificates()
        return cert_path is not None and key_path is not None


def get_ssl_context() -> SslContextTuple:
    """Return `(cert_path, key_path)` when certificates are available."""
    return SSLConfig.find_certificates()

