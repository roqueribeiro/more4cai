"""FastAPI dependencies: auth, DB session, audit context."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from orchestrator.config import settings
from orchestrator.persistence.db import get_session


async def require_token(
    x_api_token: Annotated[str | None, Header(alias="X-API-Token")] = None,
) -> str:
    """Auth simples por token compartilhado. Fase 5+ vira RBAC; Fase 6+ vira OIDC.

    Usa `hmac.compare_digest` pra defesa contra timing attack — comparação Python
    padrão (`!=`) sai cedo no primeiro byte diferente, permitindo recuperar o token
    byte-a-byte via medição de latência em rede confiável (LAN/proxy).
    """
    if not x_api_token or not hmac.compare_digest(x_api_token, settings.APP_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Token inválido",
        )
    return x_api_token


SessionDep = Annotated[AsyncSession, Depends(get_session)]
TokenDep = Annotated[str, Depends(require_token)]
