"""End-to-end pipeline: scan → normalize → dedup → AI triage → persist → report.

CLI roda síncrono. API REST enfileira via arq.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import structlog

from orchestrator.adapters.base import ScannerAdapter
from orchestrator.adapters.nmap_adapter import NmapAdapter
from orchestrator.adapters.zap_adapter import ZAPAdapter
from orchestrator.ai.analyzer import triage_batch
from orchestrator.ai.observability import emit_phase
from orchestrator.config import settings
from orchestrator.domain.dedup import heuristic_dedup
from orchestrator.domain.schemas import (
    Finding,
    ScanStatus,
    Target,
)
from orchestrator.reporting.renderer import render_html

log = structlog.get_logger(__name__)


@dataclass
class ScanResult:
    scan_id: UUID
    target: Target
    findings: list[Finding] = field(default_factory=list)
    report_path: Path | None = None
    errors: list[str] = field(default_factory=list)


async def _run_adapter(
    adapter: ScannerAdapter,
    target: Target,
    options: dict[str, Any],
    poll_every: float = 5.0,
    timeout: float = 1800.0,
    scan_id_str: str | None = None,
) -> list[Finding]:
    """Lifecycle completo de um scan: start → poll → fetch → normalize → cleanup.

    Garante via `finally` que `adapter.cleanup(handle)` seja chamado, quando
    o adapter expoe o metodo opcional. Previne vazamento de asyncio.Task,
    diretorios temp, e excecoes nao-resgatadas (H7).
    """

    if not await adapter.health():
        log.warning("adapter.unhealthy", adapter=adapter.name)
        return []

    handle = await adapter.start_scan(target, options)
    if not handle or not handle.native_id:
        log.error("adapter.invalid_handle", adapter=adapter.name)
        return []
    log.info("scan.started", adapter=adapter.name, native_id=handle.native_id)

    try:
        elapsed = 0.0
        while elapsed < timeout:
            status = await adapter.poll(handle)
            if status == ScanStatus.DONE:
                break
            if status in (ScanStatus.FAILED, ScanStatus.CANCELED):
                log.error("scan.failed", adapter=adapter.name, status=status)
                return []
            await asyncio.sleep(poll_every)
            elapsed += poll_every
        else:
            log.error("scan.timeout", adapter=adapter.name, timeout=timeout)
            return []

        raw = await adapter.fetch_results(handle)
        return await adapter.normalize(raw)
    finally:
        cleanup = getattr(adapter, "cleanup", None)
        if cleanup is not None:
            try:
                await cleanup(handle)
            except Exception as e:  # noqa: BLE001
                log.warning(
                    "adapter.cleanup_failed",
                    adapter=adapter.name,
                    native_id=handle.native_id,
                    error=str(e),
                )


async def run_scan(
    target: Target,
    *,
    adapters: list[ScannerAdapter] | None = None,
    skip_ai: bool = False,
    options: dict[str, dict[str, Any]] | None = None,
    scan_id: UUID | None = None,
    auth_headers: dict[str, str] | None = None,
    openapi_url: str | None = None,
) -> ScanResult:
    """Pipeline completo da Fase 1.

    Args:
        target: alvo da varredura.
        adapters: lista de adapters; default = [Nmap, ZAP].
        skip_ai: se True, pula AIAnalyzer (útil quando não há API key).
        options: dict por adapter — `{"nmap": {...}, "zap": {...}}`.
        scan_id: id do scan a ATUALIZAR (criado por POST /scans). None = cria novo.
    """
    scan_id = scan_id or uuid4()
    options = options or {}
    if adapters is None:
        adapters = [
            NmapAdapter(),
            ZAPAdapter(base_url=settings.ZAP_BASE_URL, api_key=settings.ZAP_API_KEY),
        ]

    result = ScanResult(scan_id=scan_id, target=target)
    sid = str(scan_id)
    # Cria ScanRow upfront pra que AIRun.scan_id (FK) seja válido durante triage
    await _ensure_scan_row(scan_id, target)
    await _update_phase(scan_id, "queued")
    emit_phase(sid, "queued")

    # roda adapters em sequência (na fase 1, simples). Paralelo vem com arq.
    for adapter in adapters:
        phase = f"{adapter.name}_running"
        await _update_phase(scan_id, phase)
        emit_phase(sid, phase)
        adapter_opts = dict(options.get(adapter.name, {}))
        # Authenticated scanning: feed the auth context to the HTTP scanners
        # ONLY (nmap is a port scanner — headers/openapi are meaningless there).
        # The secret never lands here from the persisted scan row; it arrives
        # as an ephemeral job arg (see run_scan_job).
        if adapter.name in ("zap", "nuclei"):
            if auth_headers:
                adapter_opts["headers"] = auth_headers
            if openapi_url:
                adapter_opts["openapi_url"] = openapi_url
        try:
            findings = await _run_adapter(adapter, target, adapter_opts, scan_id_str=sid)
            for f in findings:
                f.scan_id = scan_id  # sobrescreve placeholder dos adapters
            result.findings.extend(findings)
        except Exception as e:  # noqa: BLE001
            log.exception("adapter.crashed", adapter=adapter.name, error=str(e))
            result.errors.append(f"{adapter.name}: {e}")

    # Dedupe heurístico (rápido, determinístico)
    await _update_phase(scan_id, "dedup")
    emit_phase(sid, "dedup")
    result.findings = heuristic_dedup(result.findings)

    # AI triage
    if not skip_ai and result.findings:
        await _update_phase(scan_id, "ai_triage")
        emit_phase(sid, "ai_triage")
        try:
            # Triage EVERY finding (skip_severities=set()) — hardened targets
            # often yield only low/info findings, and skipping them meant the AI
            # never ran at all ("connected a key but it's not using AI"). The AI
            # is the whole value prop, so always exercise it.
            await triage_batch(result.findings, scan_id=scan_id, skip_severities=set())
        except Exception as e:  # noqa: BLE001
            log.exception("ai.triage_failed", error=str(e))
            result.errors.append(f"ai_triage: {e}")

    # Persistência (Fase 2+) — best-effort: se DB indisponível, segue com HTML
    await _update_phase(scan_id, "persisting")
    emit_phase(sid, "persisting")
    try:
        await _persist_findings(scan_id, target, result.findings)
    except Exception as e:  # noqa: BLE001
        log.warning("persist.failed", error=str(e))
        result.errors.append(f"persist: {e}")

    # report
    await _update_phase(scan_id, "reporting")
    emit_phase(sid, "reporting")
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = settings.REPORTS_DIR / f"scan-{scan_id}.html"
    render_html(result, report_path)
    result.report_path = report_path

    final_phase = "failed" if result.errors and not result.findings else "done"
    await _update_phase(scan_id, final_phase)
    emit_phase(sid, final_phase)

    log.info(
        "scan.complete",
        scan_id=str(scan_id),
        findings=len(result.findings),
        report=str(report_path),
        errors=result.errors,
    )

    # cleanup HTTP clients
    for adapter in adapters:
        if hasattr(adapter, "aclose"):
            await adapter.aclose()  # type: ignore[attr-defined]

    return result


async def _ensure_scan_row(scan_id: UUID, target: Target) -> None:
    """Best-effort: cria/garante TargetRow + ScanRow(state=running) upfront.

    Necessário pra que AIRun.scan_id (FK -> scans.id) seja válido durante
    triage. Se DB indisponível, falha silenciosa (telemetria perdida, mas
    scan continua).
    """
    try:
        from sqlmodel import select

        from orchestrator.persistence.db import session
        from orchestrator.persistence.models import ScanRow, ScanState, TargetRow

        async with session() as s:
            existing = (
                await s.exec(select(TargetRow).where(TargetRow.value == target.value))
            ).first()
            if existing is None:
                target_row = TargetRow(
                    asset_type=target.asset_type.value,
                    value=target.value,
                    label=target.label,
                    criticality=target.criticality.value,
                    contains_pii=target.contains_pii,
                )
                s.add(target_row)
                await s.flush()
            else:
                target_row = existing

            # Upsert: POST /scans already created this ScanRow (state=pending) and
            # the UI is watching that id — so UPDATE it to running instead of
            # inserting a duplicate (which would collide on the PK and orphan the
            # UI's scan in `pending` forever). Only create when truly absent.
            scan_row = await s.get(ScanRow, scan_id)
            if scan_row is None:
                scan_row = ScanRow(
                    id=scan_id,
                    target_id=target_row.id,
                    state=ScanState.RUNNING.value,
                )
                s.add(scan_row)
            else:
                scan_row.state = ScanState.RUNNING.value
                if not scan_row.target_id:
                    scan_row.target_id = target_row.id
                s.add(scan_row)
            await s.commit()
    except Exception as e:  # noqa: BLE001
        log.warning("scan.upfront_persist_failed", scan_id=str(scan_id), error=str(e))


async def _update_phase(scan_id: UUID, phase: str, progress: int | None = None) -> None:
    """Best-effort: atualiza ScanRow.current_phase. Falha silenciosamente."""
    try:
        from orchestrator.persistence.db import session
        from orchestrator.persistence.models import ScanRow

        async with session() as s:
            row = await s.get(ScanRow, scan_id)
            if row is None:
                return
            row.current_phase = phase
            row.phase_progress = progress
            await s.commit()
    except Exception as e:  # noqa: BLE001
        log.debug("phase.update_failed", scan_id=str(scan_id), phase=phase, error=str(e))


async def _persist_findings(scan_id: Any, target: Target, findings: list[Finding]) -> None:
    """Best-effort: grava Findings em DB. Silencia falha (DB pode não estar ar)."""
    from orchestrator.persistence.db import session
    from orchestrator.persistence.models import FindingRow, ScanRow, ScanState, TargetRow

    async with session() as s:
        # acha-or-cria target
        from sqlmodel import select

        existing = (await s.exec(select(TargetRow).where(TargetRow.value == target.value))).first()
        if existing is None:
            target_row = TargetRow(
                asset_type=target.asset_type.value,
                value=target.value,
                label=target.label,
                criticality=target.criticality.value,
                contains_pii=target.contains_pii,
            )
            s.add(target_row)
            await s.flush()
        else:
            target_row = existing

        # ScanRow já criado em _ensure_scan_row. Atualiza pra DONE.
        existing_scan = await s.get(ScanRow, scan_id)
        if existing_scan is not None:
            existing_scan.state = ScanState.DONE.value
            existing_scan.target_id = target_row.id
            s.add(existing_scan)
        else:
            s.add(ScanRow(id=scan_id, target_id=target_row.id, state=ScanState.DONE.value))
        await s.flush()

        for f in findings:
            s.add(
                FindingRow(
                    scan_id=scan_id,
                    target_id=target_row.id,
                    deduped_key=f.deduped_key,
                    source_tool=f.source_tool,
                    source_rule_id=f.source_rule_id,
                    vuln_id=f.vuln_id,
                    title=f.title,
                    severity=(
                        f.ai_triage.adjusted_severity.value if f.ai_triage else f.severity.value
                    ),
                    confidence=f.confidence.value,
                    payload=f.model_dump(mode="json"),
                )
            )
        await s.commit()
