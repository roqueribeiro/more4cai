"""DefectDojo export — envia findings de um Scan pro DefectDojo via API.

DefectDojo aceita upload de relatórios de scanners conhecidos via endpoint
`/api/v2/import-scan/`. Usa o "Generic Findings Import" (formato JSON) pra
mandar nossos Findings normalizados sem precisar de parser específico.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import httpx
import structlog
from sqlmodel import select

from orchestrator.config import settings
from orchestrator.persistence.db import session
from orchestrator.persistence.models import FindingRow, ScanRow, TargetRow

log = structlog.get_logger(__name__)


_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


async def export_scan(
    scan_id: UUID,
    *,
    engagement_id: int | None = None,
    product_name: str = "CAI Pipeline",
) -> dict[str, Any]:
    """Exporta findings de um scan pro DefectDojo.

    Returns:
        Resposta da API DefectDojo com test_id criado.
    """

    if not settings.DEFECTDOJO_URL or not settings.DEFECTDOJO_API_KEY:
        raise RuntimeError("DEFECTDOJO_URL/API_KEY não configurados")

    async with session() as s:
        scan = await s.get(ScanRow, scan_id)
        if scan is None:
            raise ValueError(f"scan {scan_id} não encontrado")
        target = await s.get(TargetRow, scan.target_id)
        rows = (await s.exec(select(FindingRow).where(FindingRow.scan_id == scan_id))).all()

    # Generic Findings Import format
    findings_json = {
        "findings": [
            {
                "title": r.title,
                "severity": _SEVERITY_MAP.get(r.severity, "Info"),
                "description": r.payload.get("description", ""),
                "mitigation": r.payload.get("remediation", ""),
                "vuln_id_from_tool": r.source_rule_id,
                "cve": r.vuln_id,
                "cwe": (r.payload.get("cwe") or [None])[0],
                "tags": [r.source_tool, r.confidence],
                "unique_id_from_tool": r.deduped_key,
            }
            for r in rows
        ]
    }

    headers = {"Authorization": f"Token {settings.DEFECTDOJO_API_KEY}"}
    files = {
        "file": (
            f"cai-{scan_id}.json",
            json.dumps(findings_json).encode("utf-8"),
            "application/json",
        )
    }
    data: dict[str, Any] = {
        "scan_type": "Generic Findings Import",
        "scan_date": scan.created_at.date().isoformat(),
        "active": True,
        "verified": True,
        "minimum_severity": "Info",
        "product_name": product_name,
    }
    if engagement_id is not None:
        data["engagement"] = engagement_id
    if target:
        data["service"] = target.label or target.value

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{settings.DEFECTDOJO_URL.rstrip('/')}/api/v2/import-scan/",
            headers=headers,
            data=data,
            files=files,
        )
        resp.raise_for_status()
        result = resp.json()

    log.info(
        "defectdojo.exported", scan_id=str(scan_id), test_id=result.get("test"), count=len(rows)
    )
    return result
