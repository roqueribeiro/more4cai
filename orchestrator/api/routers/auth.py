"""Auth router — login SSO (OIDC) + sessão.

Fluxo: `GET /auth/login` → redireciona pro IdP (Entra ID / Keycloak / Okta) →
`GET /auth/callback` valida o ID token (authlib: assinatura via JWKS + nonce +
aud + exp), faz find-or-provision do usuário, audita `user.login`, e emite uma
**sessão JWT** que o cliente envia em `Authorization: Bearer <jwt>`.

Habilitado só quando `OIDC_ISSUER` + `OIDC_CLIENT_ID` + `OIDC_CLIENT_SECRET`
estão setados; senão os endpoints retornam 503.
"""

from __future__ import annotations

import structlog
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from orchestrator.api.deps import PrincipalDep, SessionDep
from orchestrator.audit import log_audit_event
from orchestrator.auth import find_or_provision, issue_session
from orchestrator.config import settings

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

oauth = OAuth()
_OIDC_READY = bool(
    settings.OIDC_ISSUER and settings.OIDC_CLIENT_ID and settings.OIDC_CLIENT_SECRET
)
if _OIDC_READY:
    oauth.register(
        name="idp",
        server_metadata_url=(
            settings.OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"
        ),
        client_id=settings.OIDC_CLIENT_ID,
        client_secret=settings.OIDC_CLIENT_SECRET,
        client_kwargs={"scope": "openid email profile"},
    )


def _require_oidc() -> None:
    if not _OIDC_READY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO/OIDC não configurado (defina OIDC_ISSUER/CLIENT_ID/CLIENT_SECRET).",
        )


@router.get("/login")
async def login(request: Request):
    """Inicia o fluxo OIDC — redireciona o browser pro IdP."""
    _require_oidc()
    redirect_uri = settings.OIDC_REDIRECT_URI or str(request.url_for("oidc_callback"))
    return await oauth.idp.authorize_redirect(request, redirect_uri)


@router.get("/callback", name="oidc_callback")
async def callback(request: Request, session: SessionDep) -> JSONResponse:
    """Recebe o code do IdP → valida → provisiona usuário → emite sessão JWT."""
    _require_oidc()
    try:
        token = await oauth.idp.authorize_access_token(request)
    except OAuthError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"falha no SSO: {e.error}") from e

    userinfo = token.get("userinfo")
    if not userinfo:
        userinfo = await oauth.idp.userinfo(token=token)
    sub = userinfo.get("sub")
    if not sub:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "ID token sem 'sub'")

    user = await find_or_provision(
        session, sub=sub, email=userinfo.get("email"), name=userinfo.get("name")
    )
    if not user.active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "usuário desativado")

    await log_audit_event(
        session,
        action="user.login",
        actor=user.email,
        resource_type="user",
        resource_id=user.id,
        metadata={"via": "oidc", "idp_subject": sub},
    )
    await session.commit()
    await session.refresh(user)

    jwt_token = issue_session(user_id=user.id, email=user.email, role=user.role)
    ttl = settings.SESSION_TTL_HOURS * 3600
    resp = JSONResponse(
        {
            "access_token": jwt_token,
            "token_type": "bearer",
            "expires_in": ttl,
            "user": {"id": str(user.id), "email": user.email, "role": user.role},
        }
    )
    # cookie httpOnly pra um dashboard same-origin (o header Bearer é o canal
    # primário, imune a CSRF; o cookie é conveniência).
    resp.set_cookie(
        "cai_session", jwt_token, httponly=True, secure=True, samesite="lax", max_age=ttl
    )
    return resp


@router.get("/me")
async def me(principal: PrincipalDep) -> dict:
    """Identidade autenticada corrente (serve pra qualquer credencial válida)."""
    return {
        "id": principal.id,
        "email": principal.email,
        "role": principal.role.value,
        "is_service": principal.is_service,
    }
