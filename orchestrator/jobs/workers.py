"""arq workers — funções que rodam scans em background.

Wraps run_scan() e run_exposure_scan() em job assíncrono.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog

from orchestrator.domain.schemas import AssetType, Severity, Target

log = structlog.get_logger(__name__)


async def run_scan_job(
    ctx: dict,
    *,
    target_value: str,
    asset_type: str,
    criticality: str = "medium",
    contains_pii: bool = False,
    scanners: list[str] | None = None,
    options: dict[str, dict[str, Any]] | None = None,
    actor: str | None = None,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Job arq: roda pipeline de scan completo."""
    from orchestrator.jobs.pipelines import run_scan

    target = Target(
        asset_type=AssetType(asset_type),
        value=target_value,
        criticality=Severity(criticality),
        contains_pii=contains_pii,
    )

    log.info("scan.started", target=target_value, scanners=scanners, actor=actor)

    # Pass the requested scan_id so the pipeline UPDATES the scan POST /scans
    # created (the one the UI is watching) instead of minting a new id — which
    # left the UI's scan stuck in `pending` forever.
    result = await run_scan(
        target,
        options=options or {},
        scan_id=UUID(scan_id) if scan_id else None,
    )

    log.info(
        "scan.finished",
        scan_id=str(result.scan_id),
        findings=len(result.findings),
        errors=result.errors,
        actor=actor,
    )

    return {
        "scan_id": str(result.scan_id),
        "findings": len(result.findings),
        "errors": result.errors,
        "report_path": str(result.report_path) if result.report_path else None,
    }


async def run_exposure_job(
    ctx: dict,
    *,
    company_name: str,
    domains: list[str] | None = None,
    github_orgs: list[str] | None = None,
    dorks: list[str] | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """Job arq: pipeline OSINT/Exposure."""
    from orchestrator.jobs.exposure import run_exposure_scan

    log.info("exposure.started", company=company_name, domains=domains, github_orgs=github_orgs)

    result = await run_exposure_scan(
        company_name=company_name,
        domains=domains or [],
        github_orgs=github_orgs or [],
        dorks=dorks or [],
    )

    log.info(
        "exposure.finished",
        scan_id=str(result.scan_id),
        findings=len(result.findings),
        errors=result.errors,
    )

    return {
        "scan_id": str(result.scan_id),
        "findings": len(result.findings),
        "errors": result.errors,
        "report_path": str(result.report_path) if result.report_path else None,
    }
