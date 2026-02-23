from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, Date, DateTime, Float, ForeignKey, Integer, Text, func
from sqlalchemy.orm import DeclarativeMeta, declarative_base

Base: DeclarativeMeta = declarative_base()


class AuthUser(Base):
    __tablename__ = "auth_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(Text, unique=True, nullable=False)
    password = Column(Text, nullable=False)
    role = Column(Text, nullable=False, default="user", server_default="user")
    totp_secret = Column(Text, nullable=True)
    totp_enabled = Column(Boolean, nullable=False, default=True, server_default="1")
    security_question = Column(Text, nullable=True)
    security_answer = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text, nullable=False)
    email = Column(Text, unique=True, nullable=True)
    department = Column(Text, nullable=True)
    salary = Column(Float, nullable=True)
    hire_date = Column(Date, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, server_default="1")


class Department(Base):
    __tablename__ = "departments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text, unique=True, nullable=False)
    budget = Column(Float, nullable=True)
    manager_id = Column(Integer, ForeignKey("employees.id"), nullable=True)


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)
    start_date = Column(Date, nullable=True)
    end_date = Column(Date, nullable=True)
    status = Column(Text, nullable=False, default="active", server_default="active")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=True)
    action = Column(Text, nullable=True)
    table_name = Column(Text, nullable=True)
    query = Column(Text, nullable=True)
    prev_hash = Column(Text, nullable=True)
    entry_hash = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())
