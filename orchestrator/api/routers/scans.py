"""Scans router — POST /scans dispara via arq, GET retorna status."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from arq import create_pool
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel import select

from orchestrator.api.deps import SessionDep, TokenDep
from orchestrator.jobs.queue import _redis_settings
from orchestrator.persistence.models import ScanRow, ScanState, TargetRow

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanIn(BaseModel):
    target_id: UUID
    profile: str = "web"  # web | network | exposure | cloud | full
    scanners: list[str] = Field(default_factory=lambda: ["nmap", "zap"])
    options: dict = Field(default_factory=dict)
    actor: str | None = None


class ScanOut(BaseModel):
    id: UUID
    target_id: UUID
    state: str
    profile: str
    started_at: datetime | None
    finished_at: datetime | None
    report_path: str | None
    errors: list[str]


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    body: ScanIn,
    session: SessionDep,
    _token: TokenDep,
) -> ScanOut:
    target = await session.get(TargetRow, body.target_id)
    if target is None:
        raise HTTPException(404, "target não encontrado")

    scan = ScanRow(
        target_id=target.id,
        state=ScanState.PENDING.value,
        profile=body.profile,
        requested_scanners=body.scanners,
        options=body.options,
        actor=body.actor,
    )
    session.add(scan)
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
        options=body.options,
        actor=body.actor,
        scan_id=str(scan.id),
        _job_id=f"scan-{scan.id}",
    )

    return _to_out(scan)


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: UUID, session: SessionDep, _token: TokenDep) -> ScanOut:
    scan = await session.get(ScanRow, scan_id)
    if scan is None:
        raise HTTPException(404, "scan não encontrado")
    return _to_out(scan)


@router.get("", response_model=list[ScanOut])
async def list_scans(
    session: SessionDep,
    _token: TokenDep,
    state: str | None = None,
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
        started_at=s.started_at,
        finished_at=s.finished_at,
        report_path=s.report_path,
        errors=list(s.errors or []),
    )
