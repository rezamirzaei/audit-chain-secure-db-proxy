"""Compatibility facade for domain services.

Historically, the project kept all domain logic in `database_server.services`.
Those implementations now live in `database_server.domain.*` modules.
"""

from __future__ import annotations

from .domain.audit import AuditService as AuditService
from .domain.audit import build_audit_payload as build_audit_payload
from .domain.audit import hash_audit_payload as hash_audit_payload
from .domain.audit import verify_audit_chain as verify_audit_chain
from .domain.querying import QueryService as QueryService
from .domain.schema import SchemaService as SchemaService
from .domain.tables import TableService as TableService
from .domain.users import UserService as UserService

__all__ = [
    "AuditService",
    "QueryService",
    "SchemaService",
    "TableService",
    "UserService",
    "build_audit_payload",
    "hash_audit_payload",
    "verify_audit_chain",
]

