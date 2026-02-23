from __future__ import annotations

import importlib

_app_module = importlib.import_module(f"{__package__}.app" if __package__ else "app")
create_app = _app_module.create_app

app = create_app()
