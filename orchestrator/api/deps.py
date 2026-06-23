"""FastAPI dependencies: auth (principal + RBAC), DB session, audit context.

Modelo de autenticação (backward-compatible):

1. **Token de serviço** (`APP_TOKEN`) — o token global compartilhado continua
   válido e mapeia para um `Principal` de **serviço com papel ADMIN**. É o que
   a integração RoqueShield injeta (`X-API-Token`), então nada quebra.
2. **Token por-usuário** — cada `UserRow` tem um token (hash SHA-256); o
   `Principal` carrega a identidade real (id/email) + o papel do usuário.

`require_permission(perm)` é o gate de RBAC; o `Principal` retornado também
serve como `actor` real no audit log (antes era string livre).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from orchestrator.config import settings
from orchestrator.domain.roles import Permission, Role, coerce_role, has_permission
from orchestrator.persistence.db import get_session
from orchestrator.persistence.models import UserRow

SessionDep = Annotated[AsyncSession, Depends(get_session)]


@dataclass(frozen=True)
class Principal:
    """Identidade autenticada (usuário nomeado ou principal de serviço)."""

    id: str
    email: str
    role: Role
    is_service: bool


# Principal do token de serviço (`APP_TOKEN`) — admin, sem hit no DB.
SERVICE_PRINCIPAL = Principal(
    id="service", email="service@local", role=Role.ADMIN, is_service=True
)


def token_hash(token: str) -> str:
    """SHA-256 hex do token por-usuário (o que guardamos no DB)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def get_principal(
    session: SessionDep,
    x_api_token: Annotated[str | None, Header(alias="X-API-Token")] = None,
) -> Principal:
    """Resolve o `Principal` a partir do header `X-API-Token`.

    Ordem: (1) token de serviço (`APP_TOKEN`, comparação timing-safe, sem DB);
    (2) token por-usuário (lookup por hash). 401 se nenhum casar.
    """
    if not x_api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="X-API-Token ausente"
        )

    # 1) token de serviço — compare_digest evita timing attack; não toca o DB.
    if hmac.compare_digest(x_api_token, settings.APP_TOKEN):
        return SERVICE_PRINCIPAL

    # 2) token por-usuário — lookup pelo hash (indexado, único).
    user = (
        await session.exec(
            select(UserRow).where(UserRow.api_token_hash == token_hash(x_api_token))
        )
    ).first()
    if user is not None and user.active:
        return Principal(
            id=str(user.id),
            email=user.email,
            role=coerce_role(user.role),
            is_service=False,
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="X-API-Token inválido"
    )


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def require_permission(permission: Permission):
    """Factory de dependency: exige `permission` do principal autenticado.

    Retorna o `Principal` (pra o endpoint usar como `actor`), ou 403.
    """

    async def _dep(principal: PrincipalDep) -> Principal:
        if not has_permission(principal.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"permissão insuficiente ({permission.value})",
            )
        return principal

    return _dep


# Gates de RBAC prontos pra usar como default de parâmetro nos routers:
#   async def endpoint(..., _principal: Principal = RequireScansRead): ...
RequireScansRun = Depends(require_permission(Permission.SCANS_RUN))
RequireScansRead = Depends(require_permission(Permission.SCANS_READ))
RequireUsersManage = Depends(require_permission(Permission.USERS_MANAGE))
RequireAuditRead = Depends(require_permission(Permission.AUDIT_READ))
RequireConfigManage = Depends(require_permission(Permission.CONFIG_MANAGE))


# --- backward-compat -------------------------------------------------------
# Endpoints legados usam `_token: TokenDep` só pra exigir autenticação. Mantido
# funcionando (agora aceita token de serviço OU de usuário); novos endpoints
# devem usar `PrincipalDep` / `require_permission` / os gates acima.
async def require_token(principal: PrincipalDep) -> str:
    return principal.email


TokenDep = Annotated[str, Depends(require_token)]
