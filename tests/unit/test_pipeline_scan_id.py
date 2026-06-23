"""Regression: run_scan must UPDATE the scan id it was given (created by
POST /scans) instead of minting a new one. Before the fix the pipeline always
called uuid4(), so the requested scan stayed `pending` forever and the UI was
stuck on a scan that never progressed (results landed under a different id)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

from orchestrator.domain.schemas import AssetType, Severity, Target


def _target() -> Target:
    return Target(
        asset_type=AssetType.DOMAIN,
        value="example.com",
        criticality=Severity.MEDIUM,
        contains_pii=False,
    )


def _patches(pipelines, tmp_path):
    """Stub out every side-effect so we isolate the scan_id wiring."""
    return [
        patch.object(pipelines, "_ensure_scan_row", new=AsyncMock()),
        patch.object(pipelines, "_update_phase", new=AsyncMock()),
        patch.object(pipelines, "_persist_findings", new=AsyncMock()),
        patch.object(pipelines, "emit_phase"),
        patch.object(pipelines, "render_html"),
        patch.object(pipelines.settings, "REPORTS_DIR", tmp_path),
    ]


async def test_run_scan_uses_the_passed_scan_id(tmp_path):
    from orchestrator.jobs import pipelines

    fixed = uuid.uuid4()
    ctx = [p for p in _patches(pipelines, tmp_path)]
    for p in ctx:
        p.start()
    try:
        result = await pipelines.run_scan(
            _target(), adapters=[], skip_ai=True, scan_id=fixed
        )
    finally:
        for p in ctx:
            p.stop()

    assert result.scan_id == fixed
    # report path is keyed off the SAME id (so the UI's report link resolves)
    assert str(fixed) in str(result.report_path)


async def test_run_scan_mints_an_id_when_none_given(tmp_path):
    from orchestrator.jobs import pipelines

    ctx = [p for p in _patches(pipelines, tmp_path)]
    for p in ctx:
        p.start()
    try:
        result = await pipelines.run_scan(_target(), adapters=[], skip_ai=True)
    finally:
        for p in ctx:
            p.stop()

    assert result.scan_id is not None
