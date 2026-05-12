"""Findings router — leitura, filtros, paginação."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import select

from orchestrator.api.deps import SessionDep, TokenDep
from orchestrator.persistence.models import FindingRow

router = APIRouter(prefix="/findings", tags=["findings"])


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


@router.get("", response_model=list[FindingOut])
async def list_findings(
    session: SessionDep,
    _token: TokenDep,
    scan_id: UUID | None = None,
    severity: str | None = None,
    source_tool: str | None = None,
    limit: int = Query(default=100, le=500),
) -> list[FindingOut]:
    stmt = select(FindingRow).order_by(FindingRow.discovered_at.desc()).limit(limit)
    if scan_id:
        stmt = stmt.where(FindingRow.scan_id == scan_id)
    if severity:
        stmt = stmt.where(FindingRow.severity == severity)
    if source_tool:
        stmt = stmt.where(FindingRow.source_tool == source_tool)

    rows = (await session.exec(stmt)).all()
    return [_to_out(r) for r in rows]


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: UUID, session: SessionDep, _token: TokenDep
) -> FindingOut:
    row = await session.get(FindingRow, finding_id)
    if row is None:
        raise HTTPException(404, "finding não encontrado")
    return _to_out(row)


def _to_out(r: FindingRow) -> FindingOut:
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
    )
