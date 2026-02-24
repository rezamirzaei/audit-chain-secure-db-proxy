#!/usr/bin/env python3
"""Compatibility wrapper for :mod:`database_server.tools.seed_data`."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database_server.tools.seed_data import (
    log_info as log_info,
    main as main,
    seed_departments as seed_departments,
    seed_employees as seed_employees,
    seed_projects as seed_projects,
)

__all__ = ["log_info", "seed_departments", "seed_employees", "seed_projects", "main"]


if __name__ == "__main__":
    main()
