"""Findings router — leitura, filtros, paginação + workflow de resolução.

Além da listagem legada (`GET /findings`, `GET /findings/{id}`), expõe os
endpoints que fecham o loop "escaneia → AI resolve → marca resolvido":

- `GET  /findings/queue`   — fila PAGINADA + COMPACTA (sem o `payload` gordo),
                             deduplicada por `deduped_key` (um item por problema,
                             não por instância de scan), ordenada por severity
                             (critical primeiro), filtrável por status/severity.
                             Feita pra um agente consumir página a página sem
                             estourar contexto.
- `GET  /findings/summary` — contagens severity × status (progresso).
- `POST /findings/resolve` — muda o status de um problema (por `deduped_key`)
                             + entrada no `audit_log` (compliance).

O status de resolução vive em `finding_status` (keyed por `deduped_key`), então
SOBREVIVE re-scans — ver `orchestrator.persistence.models.FindingStatusRow`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import case, func
from sqlmodel import select

from orchestrator.api.deps import (
    Principal,
    RequireScansRead,
    RequireScansRun,
    SessionDep,
)
from orchestrator.audit.logger import log_audit_event
from orchestrator.persistence.models import (
    FindingRow,
    FindingStatus,
    FindingStatusRow,
)

router = APIRouter(prefix="/findings", tags=["findings"])

# Rank de severity pra ordenar (critical primeiro) e pro filtro min_severity.
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_case():
    """Expressão SQL: severity → rank (critical=0 … info=4; desconhecido=99)."""
    return case(
        *[(FindingRow.severity == s, i) for s, i in _SEV_RANK.items()],
        else_=99,
    )


def _latest_per_key():
    """Subquery: o `discovered_at` MAIS RECENTE por `deduped_key`.

    Colapsa N instâncias (de N scans) do mesmo problema num único item.
    Postgres + SQLite (sem DISTINCT ON / window functions).
    """
    return (
        select(
            FindingRow.deduped_key.label("dk"),
            func.max(FindingRow.discovered_at).label("max_at"),
        )
        .group_by(FindingRow.deduped_key)
        .subquery()
    )


def _short(text: str | None, limit: int = 280) -> str | None:
    if not text:
        return None
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _remediation_of(payload: dict[str, Any]) -> str | None:
    triage = payload.get("ai_triage") or {}
    return _short(triage.get("suggested_remediation") or payload.get("remediation"))


def _target_of(payload: dict[str, Any]) -> str | None:
    return (payload.get("target") or {}).get("value")


# --------------------------------------------------------------------------- #
# Compact paginated queue (AI-friendly) — declarada ANTES de /{finding_id}    #
# pra não ser engolida pela rota com path-param.                              #
# --------------------------------------------------------------------------- #


class QueueItem(BaseModel):
    finding_id: UUID  # row mais recente — use em GET /findings/{id} pro detalhe
    scan_id: UUID
    deduped_key: str
    severity: str
    status: str
    confidence: str
    source_tool: str
    vuln_id: str | None
    owasp: str | None
    cwe: list[str]
    title: str
    target: str | None
    remediation: str | None
    note: str | None  # nota da última mudança de status (se houver)


class QueuePage(BaseModel):
    items: list[QueueItem]
    total: int
    offset: int
    limit: int
    has_more: bool
    status_filter: str


@router.get("/queue", response_model=QueuePage)
async def findings_queue(
    session: SessionDep,
    status: str = Query(
        default="open",
        description="filtro de status: open|in_progress|resolved|false_positive|"
        "wont_fix|risk_accepted, ou 'all'",
    ),
    min_severity: str | None = Query(
        default=None, description="só essa severity e acima: critical|high|medium|low|info"
    ),
    source_tool: str | None = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=200),
    _principal: Principal = RequireScansRead,
) -> QueuePage:
    """Fila de problemas pra a AI resolver — paginada, compacta, severity-first.

    Um item por `deduped_key` (problema único, não por instância de scan). O
    status efetivo é `finding_status` (default `open`). Use `finding_id` em
    `GET /findings/{id}` pra puxar o detalhe completo de um problema.
    """
    latest = _latest_per_key()
    eff_status = func.coalesce(FindingStatusRow.status, FindingStatus.OPEN.value)

    base = (
        select(FindingRow, FindingStatusRow)
        .join(
            latest,
            (FindingRow.deduped_key == latest.c.dk)
            & (FindingRow.discovered_at == latest.c.max_at),
        )
        .outerjoin(
            FindingStatusRow, FindingRow.deduped_key == FindingStatusRow.deduped_key
        )
    )
    if status and status != "all":
        base = base.where(eff_status == status)
    if min_severity and min_severity in _SEV_RANK:
        base = base.where(_sev_case() <= _SEV_RANK[min_severity])
    if source_tool:
        base = base.where(FindingRow.source_tool == source_tool)

    total = (
        await session.exec(select(func.count()).select_from(base.subquery()))
    ).one()

    page = base.order_by(_sev_case(), FindingRow.discovered_at.desc()).offset(offset).limit(limit)
    rows = (await session.exec(page)).all()

    items: list[QueueItem] = []
    for fr, st in rows:
        payload = fr.payload or {}
        items.append(
            QueueItem(
                finding_id=fr.id,
                scan_id=fr.scan_id,
                deduped_key=fr.deduped_key,
                severity=fr.severity,
                status=st.status if st else FindingStatus.OPEN.value,
                confidence=fr.confidence,
                source_tool=fr.source_tool,
                vuln_id=fr.vuln_id,
                owasp=(payload.get("ai_triage") or {}).get("owasp_top10"),
                cwe=payload.get("cwe", []) or [],
                title=fr.title,
                target=_target_of(payload),
                remediation=_remediation_of(payload),
                note=st.note if st else None,
            )
        )

    return QueuePage(
        items=items,
        total=int(total),
        offset=offset,
        limit=limit,
        has_more=offset + len(items) < int(total),
        status_filter=status,
    )


# --------------------------------------------------------------------------- #
# Summary (progress) — severity × status                                      #
# --------------------------------------------------------------------------- #


class SummaryOut(BaseModel):
    total: int
    open: int  # open + in_progress (o que ainda precisa de ação)
    resolved: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    by_severity_status: dict[str, dict[str, int]]


@router.get("/summary", response_model=SummaryOut)
async def findings_summary(
    session: SessionDep, _principal: Principal = RequireScansRead
) -> SummaryOut:
    """Contagens por severity × status (um problema único por `deduped_key`)."""
    latest = _latest_per_key()
    eff_status = func.coalesce(FindingStatusRow.status, FindingStatus.OPEN.value).label("st")

    stmt = (
        select(FindingRow.severity, eff_status, func.count().label("n"))
        .join(
            latest,
            (FindingRow.deduped_key == latest.c.dk)
            & (FindingRow.discovered_at == latest.c.max_at),
        )
        .outerjoin(
            FindingStatusRow, FindingRow.deduped_key == FindingStatusRow.deduped_key
        )
        .group_by(FindingRow.severity, eff_status)
    )
    rows = (await session.exec(stmt)).all()

    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_sev_status: dict[str, dict[str, int]] = {}
    total = 0
    for sev, st, n in rows:
        n = int(n)
        total += n
        by_severity[sev] = by_severity.get(sev, 0) + n
        by_status[st] = by_status.get(st, 0) + n
        by_sev_status.setdefault(sev, {})[st] = n

    return SummaryOut(
        total=total,
        open=by_status.get("open", 0) + by_status.get("in_progress", 0),
        resolved=by_status.get("resolved", 0),
        by_status=by_status,
        by_severity=by_severity,
        by_severity_status=by_sev_status,
    )


# --------------------------------------------------------------------------- #
# Resolve / status change                                                     #
# --------------------------------------------------------------------------- #


class ResolveIn(BaseModel):
    deduped_key: str
    status: FindingStatus = FindingStatus.RESOLVED
    note: str | None = None


class ResolveOut(BaseModel):
    deduped_key: str
    status: str
    note: str | None
    updated_by: str | None
    updated_at: datetime
    resolved_at: datetime | None


@router.post("/resolve", response_model=ResolveOut)
async def resolve_finding(
    body: ResolveIn,
    session: SessionDep,
    principal: Principal = RequireScansRun,
) -> ResolveOut:
    """Muda o status de resolução de um problema (por `deduped_key`).

    Upsert em `finding_status` + entrada no `audit_log`. Requer `scans:run`
    (operator+). Persiste entre re-scans.
    """
    row = (
        await session.exec(
            select(FindingRow)
            .where(FindingRow.deduped_key == body.deduped_key)
            .order_by(FindingRow.discovered_at.desc())
            .limit(1)
        )
    ).first()
    if row is None:
        raise HTTPException(404, "nenhum finding com esse deduped_key")

    st = await session.get(FindingStatusRow, body.deduped_key)
    now = datetime.now(UTC)
    if st is None:
        st = FindingStatusRow(deduped_key=body.deduped_key)
        session.add(st)

    st.status = body.status.value
    st.note = body.note
    st.updated_by = principal.email
    st.updated_at = now
    if body.status == FindingStatus.RESOLVED and st.resolved_at is None:
        st.resolved_at = now
    st.last_severity = row.severity
    st.last_title = row.title
    st.target_value = _target_of(row.payload or {})

    await log_audit_event(
        session,
        action="finding.status_change",
        actor=principal.email,
        resource_type="finding",
        metadata={
            "deduped_key": body.deduped_key,
            "status": body.status.value,
            "title": row.title,
            "severity": row.severity,
        },
    )
    await session.commit()

    return ResolveOut(
        deduped_key=st.deduped_key,
        status=st.status,
        note=st.note,
        updated_by=st.updated_by,
        updated_at=st.updated_at,
        resolved_at=st.resolved_at,
    )


# --------------------------------------------------------------------------- #
# Legacy full listing (mantido — não quebrar o front/consumidores existentes) #
# --------------------------------------------------------------------------- #


class FindingOut(BaseModel):
    id: UUID
    scan_id: UUID
    target_id: UUID
    deduped_key: str
    source_tool: str
    title: str
    severity: str
    confidence: str
    vuln_id: str | None
    payload: dict[str, Any]
    status: str  # status de resolução efetivo (default "open")


@router.get("", response_model=list[FindingOut])
async def list_findings(
    session: SessionDep,
    scan_id: UUID | None = None,
    severity: str | None = None,
    source_tool: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    _principal: Principal = RequireScansRead,
) -> list[FindingOut]:
    stmt = (
        select(FindingRow, FindingStatusRow)
        .outerjoin(
            FindingStatusRow, FindingRow.deduped_key == FindingStatusRow.deduped_key
        )
        .order_by(FindingRow.discovered_at.desc())
        .offset(offset)
        .limit(limit)
    )
    if scan_id:
        stmt = stmt.where(FindingRow.scan_id == scan_id)
    if severity:
        stmt = stmt.where(FindingRow.severity == severity)
    if source_tool:
        stmt = stmt.where(FindingRow.source_tool == source_tool)

    rows = (await session.exec(stmt)).all()
    return [_to_out(fr, st) for fr, st in rows]


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: UUID, session: SessionDep, _principal: Principal = RequireScansRead
) -> FindingOut:
    row = await session.get(FindingRow, finding_id)
    if row is None:
        raise HTTPException(404, "finding não encontrado")
    st = await session.get(FindingStatusRow, row.deduped_key)
    return _to_out(row, st)


def _to_out(r: FindingRow, st: FindingStatusRow | None) -> FindingOut:
    return FindingOut(
        id=r.id,
        scan_id=r.scan_id,
        target_id=r.target_id,
        deduped_key=r.deduped_key,
        source_tool=r.source_tool,
        title=r.title,
        severity=r.severity,
        confidence=r.confidence,
        vuln_id=r.vuln_id,
        payload=r.payload,
        status=st.status if st else FindingStatus.OPEN.value,
    )
