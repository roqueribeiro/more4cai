"""RBAC — papéis, permissões e o mapa papel→permissões (lógica pura)."""

from __future__ import annotations

from orchestrator.api.deps import token_hash
from orchestrator.domain.roles import (
    Permission,
    Role,
    coerce_role,
    has_permission,
)


def test_admin_has_every_permission():
    for perm in Permission:
        assert has_permission(Role.ADMIN, perm), perm


def test_operator_can_run_and_read_but_not_manage_or_audit():
    assert has_permission(Role.OPERATOR, Permission.SCANS_RUN)
    assert has_permission(Role.OPERATOR, Permission.SCANS_READ)
    assert not has_permission(Role.OPERATOR, Permission.USERS_MANAGE)
    assert not has_permission(Role.OPERATOR, Permission.AUDIT_READ)
    assert not has_permission(Role.OPERATOR, Permission.CONFIG_MANAGE)


def test_auditor_reads_scans_and_audit_but_cannot_run():
    assert has_permission(Role.AUDITOR, Permission.SCANS_READ)
    assert has_permission(Role.AUDITOR, Permission.AUDIT_READ)
    assert not has_permission(Role.AUDITOR, Permission.SCANS_RUN)
    assert not has_permission(Role.AUDITOR, Permission.USERS_MANAGE)


def test_viewer_can_only_read_scans():
    assert has_permission(Role.VIEWER, Permission.SCANS_READ)
    for perm in Permission:
        if perm is not Permission.SCANS_READ:
            assert not has_permission(Role.VIEWER, perm), perm


def test_segregation_of_duties_operator_vs_auditor():
    # Quem dispara não lê o audit; quem audita não dispara.
    assert has_permission(Role.OPERATOR, Permission.SCANS_RUN)
    assert not has_permission(Role.OPERATOR, Permission.AUDIT_READ)
    assert has_permission(Role.AUDITOR, Permission.AUDIT_READ)
    assert not has_permission(Role.AUDITOR, Permission.SCANS_RUN)


def test_coerce_role_fail_closed():
    assert coerce_role("admin") is Role.ADMIN
    assert coerce_role("operator") is Role.OPERATOR
    # inválido / None → menor privilégio (nunca escala por engano)
    assert coerce_role(None) is Role.VIEWER
    assert coerce_role("") is Role.VIEWER
    assert coerce_role("superuser") is Role.VIEWER
    assert coerce_role("ADMIN") is Role.VIEWER  # case-sensitive de propósito


def test_token_hash_is_deterministic_and_not_plaintext():
    t = "cai_abc123"
    h = token_hash(t)
    assert h == token_hash(t)  # determinístico
    assert t not in h  # nunca expõe o token em claro
    assert len(h) == 64  # sha256 hex
    assert token_hash("cai_abc124") != h
