"""Sessão de usuário como JWT assinado (HS256).

Emitida no callback OIDC; enviada pelo cliente em `Authorization: Bearer <jwt>`.
Curta duração (`SESSION_TTL_HOURS`). A chave é `SESSION_SECRET` (ou o `APP_TOKEN`
como fallback). NÃO confiar no `role` do claim pra autorização — o
`get_principal` re-busca o usuário no DB pra pegar papel/ativo correntes (revoga
na hora ao desativar). O claim serve pra identificar a sessão, não pra autorizar.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from jose import JWTError, jwt

from orchestrator.config import settings

_ALG = "HS256"
_TYP = "session"


def _key() -> str:
    return settings.SESSION_SECRET or settings.APP_TOKEN


def issue_session(*, user_id: UUID | str, email: str, role: str, ttl_hours: int | None = None) -> str:
    """Emite um JWT de sessão pra `user_id`."""
    ttl = settings.SESSION_TTL_HOURS if ttl_hours is None else ttl_hours
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "email": email,
        "role": role,  # informativo; autorização re-busca no DB
        "typ": _TYP,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=ttl)).timestamp()),
    }
    return jwt.encode(claims, _key(), algorithm=_ALG)


def verify_session(token: str | None) -> dict | None:
    """Valida assinatura + expiração + `typ`. Retorna os claims, ou None se
    inválido/expirado/adulterado. Nunca lança."""
    if not token:
        return None
    try:
        claims = jwt.decode(token, _key(), algorithms=[_ALG])
    except JWTError:
        return None
    if claims.get("typ") != _TYP or not claims.get("sub"):
        return None
    return claims
