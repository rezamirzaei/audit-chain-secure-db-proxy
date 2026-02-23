"""Initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-02-23
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("password", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=True, server_default=sa.text("'user'")),
        sa.Column("totp_secret", sa.Text(), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), nullable=True, server_default=sa.true()),
        sa.Column("security_question", sa.Text(), nullable=True),
        sa.Column("security_answer", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("username", name="uq_auth_users_username"),
    )

    op.create_table(
        "employees",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("department", sa.Text(), nullable=True),
        sa.Column("salary", sa.Float(), nullable=True),
        sa.Column("hire_date", sa.Date(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True, server_default=sa.true()),
        sa.UniqueConstraint("email", name="uq_employees_email"),
    )

    op.create_table(
        "departments",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("budget", sa.Float(), nullable=True),
        sa.Column("manager_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["manager_id"], ["employees.id"]),
        sa.UniqueConstraint("name", name="uq_departments_name"),
    )

    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("department_id", sa.Integer(), nullable=True),
        sa.Column("start_date", sa.Date(), nullable=True),
        sa.Column("end_date", sa.Date(), nullable=True),
        sa.Column("status", sa.Text(), nullable=True, server_default=sa.text("'active'")),
        sa.ForeignKeyConstraint(["department_id"], ["departments.id"]),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.Text(), nullable=True),
        sa.Column("table_name", sa.Text(), nullable=True),
        sa.Column("query", sa.Text(), nullable=True),
        sa.Column("prev_hash", sa.Text(), nullable=True),
        sa.Column("entry_hash", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")),
    )


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("projects")
    op.drop_table("departments")
    op.drop_table("employees")
    op.drop_table("auth_users")
