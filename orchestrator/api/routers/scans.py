"""Scans router — POST /scans dispara via arq, GET retorna status.

Compliance gates aplicados em `create_scan`:
- `validate_target_value` (H4/H5): rejeita argv injection e SSRF.
- `REQUIRE_AUTH_REF`: força `authorization_ref` quando ativo (default off em dev).
- `log_audit_event`: registra `scan.create` no audit_log append-only.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from arq import create_pool
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel import delete, select

from orchestrator.api.deps import Principal, SessionDep, require_permission
from orchestrator.audit import log_audit_event
from orchestrator.config import settings
from orchestrator.domain.roles import Permission
from orchestrator.domain.target_validator import (
    TargetValidationError,
    validate_target_value,
)
from orchestrator.jobs.queue import _redis_settings
from orchestrator.persistence.models import AIRun, FindingRow, ScanRow, ScanState, TargetRow

# Gates de RBAC deste router.
_RUN = Depends(require_permission(Permission.SCANS_RUN))
_READ = Depends(require_permission(Permission.SCANS_READ))

router = APIRouter(prefix="/scans", tags=["scans"])


class AuthContext(BaseModel):
    """Contexto de autenticação pra scanning autenticado (atrás de login).

    Os `headers` (Cookie/Authorization/custom) são SEGREDOS: nunca persistem na
    tabela `scans` — viajam só como arg efêmero do job (Redis) até o worker, e
    o scrubber redige seus valores de qualquer evidência/relatório. O
    `openapi_url` NÃO é segredo (é a spec pública da API) e pode ser persistido.
    """

    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Headers injetados em toda request (ex.: Cookie, Authorization).",
    )
    openapi_url: str | None = Field(
        default=None,
        description="URL de uma spec OpenAPI/Swagger pra enumerar a superfície da API.",
    )


class ScanIn(BaseModel):
    target_id: UUID
    profile: str = "web"  # web | network | exposure | cloud | full
    scanners: list[str] = Field(default_factory=lambda: ["nmap", "zap"])
    options: dict = Field(default_factory=dict)
    auth: AuthContext | None = Field(
        default=None,
        description="Scanning autenticado — headers efêmeros + OpenAPI (ver AuthContext).",
    )
    actor: str | None = None
    authorization_ref: str | None = Field(
        default=None,
        description=(
            "Referencia formal a autorizacao do scan (ticket, change, aprovacao "
            "escrita). Exigido quando settings.REQUIRE_AUTH_REF=true."
        ),
    )


class ScanOut(BaseModel):
    id: UUID
    target_id: UUID
    state: str
    profile: str
    authorization_ref: str | None
    started_at: datetime | None
    finished_at: datetime | None
    report_path: str | None
    errors: list[str]


def split_scan_auth(
    options: dict, auth: AuthContext | None
) -> tuple[dict, dict[str, str], str | None]:
    """Separa o que PODE persistir do segredo EFÊMERO (scanning autenticado).

    Retorna `(persisted_options, auth_headers, openapi_url)`:
    - `persisted_options` = `options` + marcadores não-secretos (`authenticated`,
      `openapi_url`) — **sem** os valores dos headers. É o que vai pra `scans`.
    - `auth_headers` / `openapi_url` = segredo efêmero (vai só pro job).
    """
    persisted = dict(options or {})
    headers = dict(auth.headers) if auth and auth.headers else {}
    openapi = auth.openapi_url if auth else None
    if headers or openapi:
        persisted["authenticated"] = True
    if openapi:
        persisted["openapi_url"] = openapi  # spec pública, não é segredo
    return persisted, headers, openapi


def redact_audit_auth(audit_body: dict) -> dict:
    """Redige os VALORES dos auth headers no request_body do audit, mantendo os
    NOMES (a auditoria precisa saber QUAIS headers, não o segredo)."""
    auth = audit_body.get("auth")
    if isinstance(auth, dict) and isinstance(auth.get("headers"), dict):
        auth["headers"] = {k: "<redacted>" for k in auth["headers"]}
    return audit_body


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    body: ScanIn,
    session: SessionDep,
    principal: Principal = _RUN,
) -> ScanOut:
    target = await session.get(TargetRow, body.target_id)
    if target is None:
        raise HTTPException(404, "target não encontrado")

    # Gate 1: validar target.value contra injecao de flag e SSRF.
    # Re-valida no momento do scan (target.value poderia ter sido inserido
    # pre-allowlist em uma stack antiga sendo migrada).
    try:
        validate_target_value(target.value, asset_type=target.asset_type)
    except TargetValidationError as e:
        raise HTTPException(403, f"target rejeitado pela policy: {e}") from e

    # Gate 2: authorization_ref obrigatorio quando ativo (prod regulado).
    if settings.REQUIRE_AUTH_REF and not body.authorization_ref:
        raise HTTPException(
            403,
            "authorization_ref e obrigatorio (REQUIRE_AUTH_REF=true). "
            "Forneca o ticket/aprovacao formal do engagement.",
        )

    # Scanning autenticado: o segredo (auth.headers) NUNCA entra na tabela
    # `scans`. Helpers PUROS (testáveis) separam o que persiste do segredo
    # efêmero e redigem o audit.
    persisted_options, auth_headers, openapi_url = split_scan_auth(body.options, body.auth)
    audit_body = redact_audit_auth(body.model_dump(mode="json"))

    scan = ScanRow(
        target_id=target.id,
        state=ScanState.PENDING.value,
        profile=body.profile,
        requested_scanners=body.scanners,
        options=persisted_options,
        actor=principal.email,
        authorization_ref=body.authorization_ref,
    )
    session.add(scan)
    await session.flush()  # garante scan.id antes do audit

    # Gate 3: registra evento de auditoria no MESMO atomo da insercao.
    await log_audit_event(
        session,
        action="scan.create",
        actor=principal.email,
        resource_type="scan",
        resource_id=scan.id,
        authorization_ref=body.authorization_ref,
        request_body=audit_body,
        metadata={
            "target_value": target.value,
            "target_asset_type": target.asset_type,
            "profile": body.profile,
            "scanners": body.scanners,
            "lab_only": settings.LAB_ONLY,
        },
    )

    await session.commit()
    await session.refresh(scan)

    # enfileira no arq
    pool = await create_pool(_redis_settings())
    await pool.enqueue_job(
        "run_scan_job",
        target_value=target.value,
        asset_type=target.asset_type,
        criticality=target.criticality,
        contains_pii=target.contains_pii,
        scanners=body.scanners,
        options=persisted_options,
        actor=principal.email,
        scan_id=str(scan.id),
        # Segredo efêmero: vai pro job (Redis, consumido) — NÃO pra `scans`.
        auth_headers=auth_headers or None,
        openapi_url=openapi_url,
        _job_id=f"scan-{scan.id}",
    )

    return _to_out(scan)


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: UUID, session: SessionDep, _principal: Principal = _READ
) -> ScanOut:
    scan = await session.get(ScanRow, scan_id)
    if scan is None:
        raise HTTPException(404, "scan não encontrado")
    return _to_out(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: UUID, session: SessionDep, principal: Principal = _RUN
) -> None:
    """Apaga um scan e tudo que depende dele (findings + AI runs). Registra
    `scan.delete` no audit_log append-only antes de remover."""
    scan = await session.get(ScanRow, scan_id)
    if scan is None:
        raise HTTPException(404, "scan não encontrado")

    # Audita ANTES de apagar (o audit_log é append-only e não referencia o scan
    # por FK, então sobrevive à remoção).
    await log_audit_event(
        session,
        action="scan.delete",
        actor=principal.email,
        resource_type="scan",
        resource_id=scan_id,
        authorization_ref=None,
        metadata={"target_id": str(scan.target_id), "state": scan.state},
    )
    # Remove dependentes primeiro (FK scan_id) e depois o scan.
    await session.exec(delete(FindingRow).where(FindingRow.scan_id == scan_id))
    await session.exec(delete(AIRun).where(AIRun.scan_id == scan_id))
    await session.delete(scan)
    await session.commit()


@router.get("", response_model=list[ScanOut])
async def list_scans(
    session: SessionDep,
    state: str | None = None,
    _principal: Principal = _READ,
) -> list[ScanOut]:
    stmt = select(ScanRow).order_by(ScanRow.created_at.desc()).limit(100)
    if state:
        stmt = stmt.where(ScanRow.state == state)
    rows = (await session.exec(stmt)).all()
    return [_to_out(r) for r in rows]


def _to_out(s: ScanRow) -> ScanOut:
    return ScanOut(
        id=s.id,
        target_id=s.target_id,
        state=s.state,
        profile=s.profile,
        authorization_ref=s.authorization_ref,
        started_at=s.started_at,
        finished_at=s.finished_at,
        report_path=s.report_path,
        errors=list(s.errors or []),
    )
