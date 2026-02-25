"""Shared test helpers for app-module imports."""

from __future__ import annotations

import importlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def ensure_project_root_on_path() -> None:
    root_str = str(PROJECT_ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)


def import_fresh_app(package_name: str) -> Any:
    """Import `<package_name>.server.app` after clearing cached modules for the package."""
    ensure_project_root_on_path()
    for module_name in list(sys.modules):
        if module_name == package_name or module_name.startswith(f"{package_name}."):
            del sys.modules[module_name]
    return importlib.import_module(f"{package_name}.server.app")


@dataclass(frozen=True)
class FreshApp:
    module: Any
    app: Any


def create_fresh_app(package_name: str) -> FreshApp:
    module = import_fresh_app(package_name)
    return FreshApp(module=module, app=module.create_app())
