import importlib.util
import sys
from pathlib import Path

import pytest


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def proxy_client(tmp_path, monkeypatch):
    root_dir = Path(__file__).resolve().parents[1]
    proxy_dir = root_dir / "proxy_clone"

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("REDIS_URL", raising=False)

    module = _load_module("proxy_clone_app", proxy_dir / "app.py")
    module.app.testing = True
    with module.app.test_client() as client:
        yield client


def test_proxy_status_shape(proxy_client):
    resp = proxy_client.get("/api/status")
    assert resp.status_code == 200
    payload = resp.get_json()
    for key in ["has_credentials", "has_session", "has_totp", "has_security_answer", "auth_state"]:
        assert key in payload

