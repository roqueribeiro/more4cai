"""Log de auditoria append-only.

Política:
- Toda action sensível (criar scan, criar target, exportar bundle) chama
  `log_audit_event(...)` ANTES de retornar 2xx ao cliente.
- O scrubber é aplicado em metadata pra evitar PII em `audit_log.metadata_json`.
- Em Postgres, o trigger `audit_log_no_update` (migration 0004) rejeita
  UPDATE/DELETE — proteção em camada. Em SQLite o contrato é só no código.
- O nome do arquivo desta camada é referenciado em `CLAUDE.md`:
  "NUNCA permitir UPDATE/DELETE em audit_log". Não relaxar sem review.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

import structlog
from sqlmodel.ext.asyncio.session import AsyncSession

from orchestrator.domain.scrubber import scrub_dict
from orchestrator.persistence.models import AuditLogRow

log = structlog.get_logger(__name__)


async def log_audit_event(
    session: AsyncSession,
    *,
    action: str,
    actor: str | None = None,
    resource_type: str | None = None,
    resource_id: UUID | None = None,
    authorization_ref: str | None = None,
    request_body: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLogRow:
    """Insere uma entrada no audit_log.

    O caller é responsável por chamar `session.commit()` (ou já estar numa
    transação em commit deferido) — `log_audit_event` faz `session.add()` mas
    não comita, pra que a entrada faça parte do mesmo átomo da ação auditada.

    Args:
        action: nome curto da ação (`scan.create`, `target.create`, `bundle.export`).
        actor: identidade do operador (hoje vem do request body; futuramente do JWT).
        resource_type: tipo do recurso afetado.
        resource_id: UUID do recurso.
        authorization_ref: referência à autorização formal (ticket, change).
        request_body: body da requisição. Será scrubbado e hasheado em
            `request_hash`; valores não vão pro `metadata_json` cru.
        metadata: dict adicional. Scrubbado antes da persistência.

    Returns:
        Row inserida (já tem `id` e `created_at`).
    """
    request_hash: str | None = None
    if request_body is not None:
        canonical = json.dumps(request_body, sort_keys=True, ensure_ascii=False, default=str)
        request_hash = hashlib.sha256(canonical.encode()).hexdigest()

    scrubbed_meta: dict[str, Any] = {}
    if metadata:
        # scrub_dict aceita dict[str, object]; nossa metadata é dict[str, Any].
        scrubbed_meta = scrub_dict(metadata)  # type: ignore[arg-type]

    row = AuditLogRow(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        authorization_ref=authorization_ref,
        request_hash=request_hash,
        metadata_json=scrubbed_meta,
    )
    session.add(row)
    log.info(
        "audit.event",
        action=action,
        actor=actor,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        authorization_ref=authorization_ref,
    )
    return row
