"""Find-or-provision de usuário OIDC — sessão de DB mockada."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from orchestrator.auth.provisioning import find_or_provision
from orchestrator.domain.roles import Role
from orchestrator.persistence.models import UserRow


def _result(value: UserRow | None) -> MagicMock:
    r = MagicMock()
    r.first.return_value = value
    return r


def _session(exec_returns: list[UserRow | None]) -> MagicMock:
    s = MagicMock()
    s.exec = AsyncMock(side_effect=[_result(v) for v in exec_returns])
    s.add = MagicMock()
    s.flush = AsyncMock()
    return s


async def test_provisions_new_user_with_default_role():
    s = _session([None, None])  # não acha por sub nem por email
    u = await find_or_provision(s, sub="idp|123", email="New@Bank.com", name="New User")
    assert u.idp_subject == "idp|123"
    assert u.email == "new@bank.com"  # normalizado lowercase
    assert u.role == Role.VIEWER.value  # default fail-closed
    assert u.name == "New User"
    s.add.assert_called()
    s.flush.assert_awaited()


async def test_matches_existing_by_idp_subject():
    existing = UserRow(
        email="op@bank.com", role="operator", idp_subject="idp|123", active=True
    )
    s = _session([existing])  # acha por sub → não consulta email
    u = await find_or_provision(s, sub="idp|123", email="op@bank.com")
    assert u is existing
    assert u.role == "operator"  # papel preservado, não reprovisiona
    assert u.last_login_at is not None


async def test_links_subject_to_preexisting_email():
    pre = UserRow(email="admin@bank.com", role="admin", idp_subject=None, active=True)
    s = _session([None, pre])  # sub não acha; email acha (sem idp_subject)
    u = await find_or_provision(s, sub="idp|new", email="Admin@Bank.com")
    assert u is pre
    assert u.idp_subject == "idp|new"  # vincula o sub ao usuário pré-criado
    assert u.role == "admin"  # papel pré-existente mantido
