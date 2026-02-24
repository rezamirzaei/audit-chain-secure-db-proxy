#!/usr/bin/env python3
"""Idempotent seed script for demo data."""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path
from typing import Any

from sqlalchemy import select

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database_server.db import DatabaseSessionManager, init_db
from database_server.models import Department, Employee, Project


def log_info(msg: str, *args: Any) -> None:
    if args:
        try:
            msg = msg % args
        except Exception:
            msg = f"{msg} {args}"
    print(msg)


def seed_departments(session) -> int:
    departments = [
        ("Research", 400000, None),
        ("Customer Success", 220000, None),
        ("Operations", 180000, None),
        ("IT Support", 160000, None),
        ("Legal", 210000, None),
    ]

    added = 0
    for name, budget, manager_id in departments:
        exists = session.execute(select(Department.id).where(Department.name == name)).scalar_one_or_none()
        if exists is not None:
            continue
        session.add(Department(name=name, budget=budget, manager_id=manager_id))
        added += 1
    return added


def seed_employees(session) -> int:
    employees = [
        ("Priya Patel", "priya.patel@company.com", "Research", 120000, "2019-05-12", True),
        ("Carlos Diaz", "carlos.diaz@company.com", "Operations", 72000, "2022-02-10", True),
        ("Hannah Lee", "hannah.lee@company.com", "Customer Success", 68000, "2021-11-03", True),
        ("Omar Hassan", "omar.hassan@company.com", "IT Support", 78000, "2020-09-17", True),
        ("Grace Kim", "grace.kim@company.com", "Legal", 115000, "2018-03-25", True),
        ("Mina Zhao", "mina.zhao@company.com", "Research", 132000, "2017-07-08", True),
    ]

    added = 0
    for name, email, dept, salary, hire_date, is_active in employees:
        exists = session.execute(select(Employee.id).where(Employee.email == email)).scalar_one_or_none()
        if exists is not None:
            continue
        session.add(
            Employee(
                name=name,
                email=email,
                department=dept,
                salary=salary,
                hire_date=date.fromisoformat(hire_date),
                is_active=is_active,
            )
        )
        added += 1
    return added


def seed_projects(session) -> int:
    session.flush()
    dept_rows = session.execute(select(Department.id, Department.name)).all()
    dept_map = {name: dept_id for dept_id, name in dept_rows}

    projects = [
        ("AI Forecasting", "Predictive analytics for sales and staffing", "Research", "2024-05-01", "2025-01-31", "active"),
        ("Customer Onboarding 2.0", "Reduce time-to-value with guided flows", "Customer Success", "2024-02-15", "2024-10-31", "active"),
        ("IT Service Desk Revamp", "Upgrade ticketing and knowledge base", "IT Support", "2024-01-10", "2024-07-31", "completed"),
        ("Ops Automation", "Automate recurring finance ops tasks", "Operations", "2024-03-05", "2024-12-15", "active"),
        ("Compliance Readiness", "Prepare for annual compliance audit", "Legal", "2024-04-01", "2024-09-30", "planning"),
    ]

    added = 0
    for name, description, dept_name, start_date, end_date, status in projects:
        exists = session.execute(select(Project.id).where(Project.name == name)).scalar_one_or_none()
        if exists is not None:
            continue
        dept_id = dept_map.get(dept_name)
        if dept_id is None:
            continue
        session.add(
            Project(
                name=name,
                description=description,
                department_id=dept_id,
                start_date=date.fromisoformat(start_date),
                end_date=date.fromisoformat(end_date),
                status=status,
            )
        )
        added += 1
    return added


def main() -> None:
    manager = DatabaseSessionManager.from_env()
    init_db(manager, demo_mode=True, enable_totp_test_endpoint=True, log_info=log_info)

    with manager.session() as session:
        dept_added = seed_departments(session)
        emp_added = seed_employees(session)
        proj_added = seed_projects(session)
        session.commit()

    print(f"Seed complete. Added departments={dept_added}, employees={emp_added}, projects={proj_added}")


if __name__ == "__main__":
    main()
