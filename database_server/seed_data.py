#!/usr/bin/env python3
"""Idempotent seed script for demo data."""
import os
import sqlite3
from datetime import datetime


def db_path() -> str:
    if os.path.exists('/app'):
        return '/app/data/database.db'
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'database.db')


def main() -> None:
    path = db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    cur = conn.cursor()

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
        cur.execute("SELECT 1 FROM departments WHERE name = ?", (name,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO departments (name, budget, manager_id) VALUES (?, ?, ?)",
                (name, budget, manager_id),
            )
            dept_added += 1

    # Employees
    employees = [
        ('Priya Patel', 'priya.patel@company.com', 'Research', 120000, '2019-05-12', 1),
        ('Carlos Diaz', 'carlos.diaz@company.com', 'Operations', 72000, '2022-02-10', 1),
        ('Hannah Lee', 'hannah.lee@company.com', 'Customer Success', 68000, '2021-11-03', 1),
        ('Omar Hassan', 'omar.hassan@company.com', 'IT Support', 78000, '2020-09-17', 1),
        ('Grace Kim', 'grace.kim@company.com', 'Legal', 115000, '2018-03-25', 1),
        ('Mina Zhao', 'mina.zhao@company.com', 'Research', 132000, '2017-07-08', 1),
    ]

    emp_added = 0
    for name, email, dept, salary, hire_date, is_active in employees:
        cur.execute("SELECT 1 FROM employees WHERE email = ?", (email,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO employees (name, email, department, salary, hire_date, is_active) VALUES (?, ?, ?, ?, ?, ?)",
                (name, email, dept, salary, hire_date, is_active),
            )
            emp_added += 1

    # Projects (lookup department_id)
    cur.execute("SELECT id, name FROM departments")
    dept_map = {name: dept_id for dept_id, name in cur.fetchall()}

    projects = [
        ('AI Forecasting', 'Predictive analytics for sales and staffing', 'Research', '2024-05-01', '2025-01-31', 'active'),
        ('Customer Onboarding 2.0', 'Reduce time-to-value with guided flows', 'Customer Success', '2024-02-15', '2024-10-31', 'active'),
        ('IT Service Desk Revamp', 'Upgrade ticketing and knowledge base', 'IT Support', '2024-01-10', '2024-07-31', 'completed'),
        ('Ops Automation', 'Automate recurring finance ops tasks', 'Operations', '2024-03-05', '2024-12-15', 'active'),
        ('Compliance Readiness', 'Prepare for annual compliance audit', 'Legal', '2024-04-01', '2024-09-30', 'planning'),
    ]

    proj_added = 0
    for name, description, dept_name, start_date, end_date, status in projects:
        cur.execute("SELECT 1 FROM projects WHERE name = ?", (name,))
        if cur.fetchone() is not None:
            continue
        dept_id = dept_map.get(dept_name)
        if dept_id is None:
            continue
        cur.execute(
            "INSERT INTO projects (name, description, department_id, start_date, end_date, status) VALUES (?, ?, ?, ?, ?, ?)",
            (name, description, dept_id, start_date, end_date, status),
        )
        proj_added += 1

    conn.commit()
    print(f"Seed complete. Added departments={dept_added}, employees={emp_added}, projects={proj_added}")


if __name__ == '__main__':
    main()
