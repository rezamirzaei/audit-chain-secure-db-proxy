"""Shared environment parsing helpers.

These are intentionally small and dependency-free so they can be reused across
services without dragging in Flask, Pydantic, or other frameworks.
"""

from __future__ import annotations


TRUE_VALUES = {"1", "true", "yes", "y", "on"}


def parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return default

