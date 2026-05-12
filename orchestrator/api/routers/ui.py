"""UI API endpoints — alimenta o dashboard HTML.

Rotas (prefixo `/ui/api`):
  GET  /scans            — últimos 50 scans com counts/phase
  GET  /scans/{id}        — detalhe de um scan + findings counts
  GET  /findings          — filtros: scan_id, severity, source_tool, limit
  GET  /ai-runs           — últimas 100 chamadas LLM
  GET  /ai-runs/stats     — agregações: count by model, p50/p95 latency, fallback rate
  GET  /events            — SSE: live logs + phase updates

Auth: `X-API-Token` ou `?token=...` na query (UI mesmo origem).
"""

from __future__ import annotations

import hmac
import statistics
from collections import Counter
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func
from sqlmodel import select

from orchestrator.ai.observability import sse_stream
from orchestrator.api.deps import SessionDep
from orchestrator.config import settings
from orchestrator.persistence.models import AIRun, FindingRow, ScanRow, TargetRow

router = APIRouter(prefix="/ui/api", tags=["ui"])


async def _ui_token(
    request: Request,
    x_api_token: Annotated[str | None, Header(alias="X-API-Token")] = None,
    token: Annotated[str | None, Query()] = None,
) -> str:
    """Auth UI.

    Aceita o header `X-API-Token` em qualquer endpoint. Aceita `?token=...` SOMENTE
    em `/ui/api/events` — SSE não suporta headers customizados, então a query é
    inevitável. Em todos os outros endpoints, o `?token=` é rejeitado pra evitar
    que o token vaze em logs, Referer e cache de browser.

    Compara com `hmac.compare_digest` pra mitigar timing attack.
    """
    if token is not None and not request.url.path.endswith("/events"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="?token= permitido apenas em /ui/api/events; use X-API-Token header",
        )
    provided = x_api_token or token
    if not provided or not hmac.compare_digest(provided, settings.APP_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Token inválido",
        )
    return provided


UIToken = Annotated[str, Depends(_ui_token)]


@router.get("/scans")
async def list_scans(
    session: SessionDep, _token: UIToken, limit: int = Query(default=50, le=200)
) -> list[dict[str, Any]]:
    rows = (
        await session.exec(select(ScanRow).order_by(desc(ScanRow.created_at)).limit(limit))
    ).all()
    out = []
    for s in rows:
        # counts de findings + severity dist
        findings_q = await session.exec(
            select(FindingRow.severity, func.count(FindingRow.id))
            .where(FindingRow.scan_id == s.id)
            .group_by(FindingRow.severity)
        )
        sev_counts: dict[str, int] = {r[0]: int(r[1]) for r in findings_q.all()}
        target = await session.get(TargetRow, s.target_id)
        out.append(
            {
                "id": str(s.id),
                "target_value": target.value if target else None,
                "state": s.state,
                "current_phase": s.current_phase,
                "phase_progress": s.phase_progress,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                "report_path": s.report_path,
                "errors": list(s.errors or []),
                "severity_counts": sev_counts,
                "total_findings": sum(sev_counts.values()),
            }
        )
    return out


@router.get("/scans/{scan_id}")
async def scan_detail(scan_id: UUID, session: SessionDep, _token: UIToken) -> dict[str, Any]:
    s = await session.get(ScanRow, scan_id)
    if s is None:
        raise HTTPException(404, "scan não encontrado")
    target = await session.get(TargetRow, s.target_id)
    findings_q = await session.exec(
        select(FindingRow.severity, func.count(FindingRow.id))
        .where(FindingRow.scan_id == scan_id)
        .group_by(FindingRow.severity)
    )
    sev_counts: dict[str, int] = {r[0]: int(r[1]) for r in findings_q.all()}
    ai_runs_q = await session.exec(
        select(AIRun).where(AIRun.scan_id == scan_id).order_by(desc(AIRun.created_at)).limit(20)
    )
    ai_runs = [
        {
            "id": str(a.id),
            "purpose": a.purpose,
            "model": a.model,
            "latency_ms": a.latency_ms,
            "prompt_tokens": a.prompt_tokens,
            "completion_tokens": a.completion_tokens,
            "success": a.success,
            "error": a.error,
            "finding_count": a.finding_count,
            "created_at": a.created_at.isoformat(),
        }
        for a in ai_runs_q.all()
    ]
    return {
        "id": str(s.id),
        "target": {"value": target.value, "asset_type": target.asset_type} if target else None,
        "state": s.state,
        "current_phase": s.current_phase,
        "phase_progress": s.phase_progress,
        "profile": s.profile,
        "scanners_requested": list(s.requested_scanners or []),
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "report_path": s.report_path,
        "errors": list(s.errors or []),
        "severity_counts": sev_counts,
        "ai_runs": ai_runs,
    }


@router.get("/findings")
async def list_findings(
    session: SessionDep,
    _token: UIToken,
    scan_id: UUID | None = None,
    severity: str | None = None,
    source_tool: str | None = None,
    limit: int = Query(default=100, le=500),
) -> list[dict[str, Any]]:
    stmt = select(FindingRow).order_by(desc(FindingRow.discovered_at)).limit(limit)
    if scan_id:
        stmt = stmt.where(FindingRow.scan_id == scan_id)
    if severity:
        stmt = stmt.where(FindingRow.severity == severity)
    if source_tool:
        stmt = stmt.where(FindingRow.source_tool == source_tool)

    rows = (await session.exec(stmt)).all()
    return [
        {
            "id": str(r.id),
            "scan_id": str(r.scan_id),
            "title": r.title,
            "severity": r.severity,
            "confidence": r.confidence,
            "source_tool": r.source_tool,
            "source_rule_id": r.source_rule_id,
            "vuln_id": r.vuln_id,
        }
        for r in rows
    ]


@router.get("/ai-runs")
async def list_ai_runs(
    session: SessionDep,
    _token: UIToken,
    limit: int = Query(default=100, le=500),
) -> list[dict[str, Any]]:
    rows = (await session.exec(select(AIRun).order_by(desc(AIRun.created_at)).limit(limit))).all()
    return [
        {
            "id": str(r.id),
            "scan_id": str(r.scan_id) if r.scan_id else None,
            "purpose": r.purpose,
            "model": r.model,
            "latency_ms": r.latency_ms,
            "prompt_tokens": r.prompt_tokens,
            "completion_tokens": r.completion_tokens,
            "cache_creation_tokens": r.cache_creation_tokens,
            "cache_read_tokens": r.cache_read_tokens,
            "finding_count": r.finding_count,
            "success": r.success,
            "error": r.error,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/ai-runs/stats")
async def ai_run_stats(session: SessionDep, _token: UIToken) -> dict[str, Any]:
    """Agregações leves sobre últimas 1000 calls."""
    rows = (await session.exec(select(AIRun).order_by(desc(AIRun.created_at)).limit(1000))).all()
    if not rows:
        return {
            "total": 0,
            "by_model": [],
            "latency_p50": 0,
            "latency_p95": 0,
            "fallback_rate": 0.0,
            "success_rate": 1.0,
        }
    latencies = sorted([r.latency_ms for r in rows if r.latency_ms > 0])
    by_model = Counter(r.model for r in rows)
    fallback_count = sum(1 for r in rows if r.purpose.endswith(".fallback"))
    success_count = sum(1 for r in rows if r.success)
    return {
        "total": len(rows),
        "by_model": [{"model": m, "count": c} for m, c in by_model.most_common(10)],
        "latency_p50": int(statistics.median(latencies)) if latencies else 0,
        "latency_p95": int(latencies[int(len(latencies) * 0.95)])
        if len(latencies) >= 20
        else (int(latencies[-1]) if latencies else 0),
        "fallback_rate": round(fallback_count / len(rows), 3),
        "success_rate": round(success_count / len(rows), 3),
    }


@router.get("/events")
async def events(
    request: Request,
    _token: UIToken,
    scan_id: str | None = None,
) -> StreamingResponse:
    """Server-Sent Events: live logs + phase updates pra um scan_id (opcional)."""

    async def gen():
        async for chunk in sse_stream(scan_id=scan_id):
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # nginx hint
        },
    )
