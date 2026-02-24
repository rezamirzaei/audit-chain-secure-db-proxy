#!/usr/bin/env python3
"""Compatibility wrapper for :mod:`database_server.tools.verify_audit_chain`."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database_server.tools.verify_audit_chain import main as main, verify_chain as verify_chain

__all__ = ["verify_chain", "main"]


if __name__ == "__main__":
    main()
