"""Auth: `get_principal` (token de serviço vs usuário vs inválido) + o gate
`require_permission`. Sessão de DB é mockada — testa só a lógica de auth/RBAC."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from orchestrator.api import deps
from orchestrator.api.deps import (
    Principal,
    get_principal,
    require_permission,
    token_hash,
)
from orchestrator.domain.roles import Permission, Role
from orchestrator.persistence.models import UserRow


def _session_returning(user: UserRow | None) -> MagicMock:
    """AsyncSession mockada cujo `(await session.exec(...)).first()` = `user`."""
    result = MagicMock()
    result.first.return_value = user
    session = MagicMock()
    session.exec = AsyncMock(return_value=result)
    return session


async def test_service_token_maps_to_admin_principal():
    # o APP_TOKEN global continua valendo como principal de serviço (admin) —
    # é o que a integração RoqueShield injeta; não pode quebrar.
    session = MagicMock()
    p = await get_principal(session=session, x_api_token=deps.settings.APP_TOKEN)
    assert p.is_service is True
    assert p.role is Role.ADMIN
    session.exec.assert_not_called()  # service token não toca o DB


async def test_user_token_maps_to_user_principal():
    token = "cai_user_operator_token"
    user = UserRow(
        email="op@bank.com",
        role="operator",
        api_token_hash=token_hash(token),
        active=True,
    )
    session = _session_returning(user)
    p = await get_principal(session=session, x_api_token=token)
    assert p.is_service is False
    assert p.email == "op@bank.com"
    assert p.role is Role.OPERATOR


async def test_invalid_token_is_401():
    session = _session_returning(None)
    token = "cai_does_not_exist"
    with pytest.raises(HTTPException) as ei:
        await get_principal(session=session, x_api_token=token)
    assert ei.value.status_code == 401


async def test_inactive_user_is_401():
    token = "cai_inactive_admin"
    user = UserRow(
        email="ghost@bank.com",
        role="admin",  # mesmo admin: inativo não autentica
        api_token_hash=token_hash(token),
        active=False,
    )
    session = _session_returning(user)
    with pytest.raises(HTTPException) as ei:
        await get_principal(session=session, x_api_token=token)
    assert ei.value.status_code == 401


async def test_missing_token_is_401():
    with pytest.raises(HTTPException) as ei:
        await get_principal(session=MagicMock(), x_api_token=None)
    assert ei.value.status_code == 401


async def test_require_permission_allows_then_denies():
    gate = require_permission(Permission.SCANS_RUN)
    operator = Principal(id="1", email="op@bank.com", role=Role.OPERATOR, is_service=False)
    viewer = Principal(id="2", email="v@bank.com", role=Role.VIEWER, is_service=False)

    assert (await gate(principal=operator)) is operator  # operador pode rodar
    with pytest.raises(HTTPException) as ei:
        await gate(principal=viewer)  # viewer não
    assert ei.value.status_code == 403


async def test_users_manage_is_admin_only():
    gate = require_permission(Permission.USERS_MANAGE)
    admin = Principal(id="1", email="a@bank.com", role=Role.ADMIN, is_service=False)
    operator = Principal(id="2", email="o@bank.com", role=Role.OPERATOR, is_service=False)

    assert (await gate(principal=admin)) is admin
    with pytest.raises(HTTPException) as ei:
        await gate(principal=operator)
    assert ei.value.status_code == 403
