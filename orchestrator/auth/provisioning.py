"""Find-or-provision de `UserRow` a partir dos claims do IdP (OIDC).

Ordem: (1) por `idp_subject` (o `sub` estável do IdP); (2) por `email` (vincula
o `sub` a um usuário pré-criado por um admin); (3) provisiona novo com o papel
default (`OIDC_DEFAULT_ROLE`, fail-closed = viewer). NÃO ativa um usuário
desativado — quem foi desligado continua desligado mesmo logando pelo SSO.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from orchestrator.config import settings
from orchestrator.domain.roles import coerce_role
from orchestrator.persistence.models import UserRow


async def find_or_provision(
    session: AsyncSession, *, sub: str, email: str | None, name: str | None = None
) -> UserRow:
    email = (email or "").strip().lower()

    # 1) por idp_subject (identidade estável)
    user = (
        await session.exec(select(UserRow).where(UserRow.idp_subject == sub))
    ).first()

    # 2) por email — vincula o sub a um usuário que um admin pré-criou
    if user is None and email:
        user = (await session.exec(select(UserRow).where(UserRow.email == email))).first()
        if user is not None and not user.idp_subject:
            user.idp_subject = sub

    # 3) provisiona novo (papel default, fail-closed)
    if user is None:
        user = UserRow(
            email=email or f"{sub}@oidc.local",
            name=name,
            role=coerce_role(settings.OIDC_DEFAULT_ROLE).value,
            idp_subject=sub,
        )
        session.add(user)
        await session.flush()
        return user

    user.last_login_at = datetime.now(UTC)
    if name and not user.name:
        user.name = name
    session.add(user)
    return user
