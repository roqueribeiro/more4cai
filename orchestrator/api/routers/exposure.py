"""Exposure router — Fase 2.5 OSINT scanning."""

from __future__ import annotations

from uuid import UUID

from arq import create_pool
from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from orchestrator.api.deps import TokenDep
from orchestrator.jobs.queue import _redis_settings

router = APIRouter(prefix="/exposure", tags=["exposure"])


class ExposureIn(BaseModel):
    company_name: str
    domains: list[str] = Field(default_factory=list)
    github_orgs: list[str] = Field(default_factory=list)
    dorks: list[str] = Field(default_factory=list)


class ExposureOut(BaseModel):
    job_id: str
    queued: bool


@router.post("/scan", response_model=ExposureOut, status_code=status.HTTP_202_ACCEPTED)
async def scan_exposure(body: ExposureIn, _token: TokenDep) -> ExposureOut:
    pool = await create_pool(_redis_settings())
    job = await pool.enqueue_job(
        "run_exposure_job",
        company_name=body.company_name,
        domains=body.domains,
        github_orgs=body.github_orgs,
        dorks=body.dorks,
    )
    return ExposureOut(job_id=str(job.job_id) if job else "unknown", queued=job is not None)
