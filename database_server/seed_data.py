#!/usr/bin/env python3
"""Idempotent seed script for demo data."""
import importlib
import os

_db_module = importlib.import_module(f"{__package__}.db" if __package__ else "db")
connect_db = _db_module.connect_db
init_db = _db_module.init_db

def _log_info(msg: str, *args) -> None:
    if args:
        try:
            msg = msg % args
        except Exception:
            msg = f"{msg} {args}"
    print(msg)


def main() -> None:
    retries = int(os.environ.get("DB_CONNECT_RETRIES", "30"))
    db = connect_db(retries=retries)
    init_db(db, demo_mode=True, enable_totp_test_endpoint=True, log_info=_log_info)

    # Departments
    departments = [
        ('Research', 400000, None),
        ('Customer Success', 220000, None),
        ('Operations', 180000, None),
        ('IT Support', 160000, None),
        ('Legal', 210000, None),
    ]

    dept_added = 0
    for name, budget, manager_id in departments:
        if db.execute("SELECT 1 FROM departments WHERE name = ?", (name,)).fetchone() is None:
            db.execute(
                "INSERT INTO departments (name, budget, manager_id) VALUES (?, ?, ?)",
                (name, budget, manager_id),
            )
            dept_added += 1

    # Employees
    employees = [
        ('Priya Patel', 'priya.patel@company.com', 'Research', 120000, '2019-05-12', True),
        ('Carlos Diaz', 'carlos.diaz@company.com', 'Operations', 72000, '2022-02-10', True),
        ('Hannah Lee', 'hannah.lee@company.com', 'Customer Success', 68000, '2021-11-03', True),
        ('Omar Hassan', 'omar.hassan@company.com', 'IT Support', 78000, '2020-09-17', True),
        ('Grace Kim', 'grace.kim@company.com', 'Legal', 115000, '2018-03-25', True),
        ('Mina Zhao', 'mina.zhao@company.com', 'Research', 132000, '2017-07-08', True),
    ]

    emp_added = 0
    for name, email, dept, salary, hire_date, is_active in employees:
        if db.execute("SELECT 1 FROM employees WHERE email = ?", (email,)).fetchone() is None:
            db.execute(
                "INSERT INTO employees (name, email, department, salary, hire_date, is_active) VALUES (?, ?, ?, ?, ?, ?)",
                (name, email, dept, salary, hire_date, is_active),
            )
            emp_added += 1

    # Projects (lookup department_id)
    dept_rows = db.execute("SELECT id, name FROM departments").fetchall()
    dept_map = {row["name"]: row["id"] for row in dept_rows}

    projects = [
        ('AI Forecasting', 'Predictive analytics for sales and staffing', 'Research', '2024-05-01', '2025-01-31', 'active'),
        ('Customer Onboarding 2.0', 'Reduce time-to-value with guided flows', 'Customer Success', '2024-02-15', '2024-10-31', 'active'),
        ('IT Service Desk Revamp', 'Upgrade ticketing and knowledge base', 'IT Support', '2024-01-10', '2024-07-31', 'completed'),
        ('Ops Automation', 'Automate recurring finance ops tasks', 'Operations', '2024-03-05', '2024-12-15', 'active'),
        ('Compliance Readiness', 'Prepare for annual compliance audit', 'Legal', '2024-04-01', '2024-09-30', 'planning'),
    ]

    proj_added = 0
    for name, description, dept_name, start_date, end_date, status in projects:
        if db.execute("SELECT 1 FROM projects WHERE name = ?", (name,)).fetchone() is not None:
            continue
        dept_id = dept_map.get(dept_name)
        if dept_id is None:
            continue
        db.execute(
            "INSERT INTO projects (name, description, department_id, start_date, end_date, status) VALUES (?, ?, ?, ?, ?, ?)",
            (name, description, dept_id, start_date, end_date, status),
        )
        proj_added += 1

    db.commit()
    db.close()
    print(f"Seed complete. Added departments={dept_added}, employees={emp_added}, projects={proj_added}")


if __name__ == '__main__':
    main()
