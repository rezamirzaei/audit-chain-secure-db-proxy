"""Compatibility wrapper around shared SSL helpers for proxy_clone."""

from shared.ssl_utils import SSLConfig as SSLConfig
from shared.ssl_utils import get_ssl_context as get_ssl_context

__all__ = ["SSLConfig", "get_ssl_context"]

