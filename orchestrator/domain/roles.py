"""RBAC — papéis, permissões e o mapa papel→permissões.

Modelo simples e auditável (sem dependência externa): um conjunto fixo de
permissões granulares, e cada papel é um conjunto de permissões. A checagem é
pura (`has_permission`) — testável sem DB nem FastAPI.

Princípios:
- ADMIN tem TODAS as permissões (inclui o `Principal` de serviço do `APP_TOKEN`,
  que mantém a integração RoqueShield/`X-API-Token` funcionando como hoje).
- Papéis são aditivos por permissão, nunca por hierarquia implícita — fica
  explícito o que cada papel pode, evitando "admin acidental".
- Segregação de funções: AUDITOR lê tudo + o audit log, mas NÃO dispara scan;
  OPERATOR dispara/apaga scans mas NÃO lê o audit log nem gerencia usuários.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class Permission(StrEnum):
    USERS_MANAGE = "users:manage"  # criar/listar/desativar usuários
    SCANS_RUN = "scans:run"  # criar target, disparar/apagar scan
    SCANS_READ = "scans:read"  # ler scans, findings, relatórios, AI bundle
    AUDIT_READ = "audit:read"  # ler o audit log
    CONFIG_MANAGE = "config:manage"  # escopo, allowlist, config de IA


_ALL: frozenset[Permission] = frozenset(Permission)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: _ALL,
    Role.OPERATOR: frozenset({Permission.SCANS_RUN, Permission.SCANS_READ}),
    Role.AUDITOR: frozenset({Permission.SCANS_READ, Permission.AUDIT_READ}),
    Role.VIEWER: frozenset({Permission.SCANS_READ}),
}


def has_permission(role: Role, permission: Permission) -> bool:
    """True se `role` concede `permission`. Papel desconhecido → nega tudo."""
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def coerce_role(value: str | None) -> Role:
    """Converte string → Role; valor inválido/None vira o papel de menor
    privilégio (VIEWER) — fail-closed, nunca escala privilégio por engano."""
    try:
        return Role(value) if value else Role.VIEWER
    except ValueError:
        return Role.VIEWER
