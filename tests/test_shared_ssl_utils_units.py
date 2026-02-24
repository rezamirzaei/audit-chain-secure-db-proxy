from __future__ import annotations

from pathlib import Path

from shared.ssl_utils import DEFAULT_SSL_SEARCH_PATHS, SSLConfig


def test_default_ssl_search_paths_include_service_demo_cert_locations():
    # `scripts/generate_demo_certs.sh` writes demo certs under these folders.
    assert ("database_server/certs/cert.pem", "database_server/certs/key.pem") in DEFAULT_SSL_SEARCH_PATHS
    assert ("proxy_clone/certs/cert.pem", "proxy_clone/certs/key.pem") in DEFAULT_SSL_SEARCH_PATHS
    assert ("nginx/certs/cert.pem", "nginx/certs/key.pem") in DEFAULT_SSL_SEARCH_PATHS


def test_ssl_config_can_find_first_existing_certificate_pair(tmp_path: Path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("dummy")
    key.write_text("dummy")

    original_paths = list(SSLConfig.SSL_SEARCH_PATHS)
    try:
        SSLConfig.SSL_SEARCH_PATHS = [
            ("does-not-exist.pem", "also-missing.pem"),
            (str(cert), str(key)),
        ]
        assert SSLConfig.find_certificates() == (str(cert), str(key))
        assert SSLConfig.has_certificates() is True
    finally:
        SSLConfig.SSL_SEARCH_PATHS = original_paths

