"""Audit log append-only.

Camada de aplicação. Em Postgres, append-only é reforçado por trigger
(`audit_log_no_update`, migration 0004). Em SQLite (dev), apenas pelo código.
"""

from orchestrator.audit.logger import log_audit_event

__all__ = ["log_audit_event"]
