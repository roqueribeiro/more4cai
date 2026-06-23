"""Auth/SSO — sessão JWT + provisionamento de usuário a partir do IdP (OIDC).

O login OIDC (router `orchestrator.api.routers.auth`) valida o ID token do IdP
via authlib, faz find-or-provision do `UserRow`, e emite uma **sessão JWT**
(HS256) que o cliente envia em `Authorization: Bearer <jwt>`. O `get_principal`
(em `orchestrator.api.deps`) aceita essa sessão além do `X-API-Token`.
"""

from orchestrator.auth.provisioning import find_or_provision
from orchestrator.auth.session import issue_session, verify_session

__all__ = ["find_or_provision", "issue_session", "verify_session"]
