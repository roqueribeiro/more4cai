"""Reports router — download HTML técnico/executivo, AI Fix Bundle, export DefectDojo."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from orchestrator.api.deps import SessionDep, TokenDep
from orchestrator.persistence.models import ScanRow

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{scan_id}")
async def download_report(scan_id: UUID, session: SessionDep, _token: TokenDep) -> FileResponse:
    scan = await session.get(ScanRow, scan_id)
    if scan is None or not scan.report_path:
        raise HTTPException(404, "relatório não encontrado")
    path = Path(scan.report_path)
    if not path.exists():
        raise HTTPException(404, f"arquivo {path} não existe no disco")
    return FileResponse(path, media_type="text/html", filename=path.name)


@router.get("/{scan_id}/ai-bundle")
async def download_ai_bundle(scan_id: UUID, session: SessionDep, _token: TokenDep) -> JSONResponse:
    """AI Fix Bundle — JSON estruturado pra outra IA consumir e patchar código.

    Schema versionado em `docs/ai-fix-bundle-spec.md`. Patcher externo
    (Claude Code, Cursor, Copilot) recebe esse JSON e produz patches.
    """
    from orchestrator.reporting.exporters.ai_bundle import build_bundle

    scan = await session.get(ScanRow, scan_id)
    if scan is None:
        raise HTTPException(404, "scan não encontrado")

    try:
        bundle = await build_bundle(scan_id)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"falha ao gerar bundle: {e}") from e

    return JSONResponse(content=bundle)


@router.post("/{scan_id}/export/defectdojo", status_code=202)
async def export_defectdojo(scan_id: UUID, session: SessionDep, _token: TokenDep) -> JSONResponse:
    """Exporta findings desse scan pro DefectDojo via API."""
    from orchestrator.reporting.exporters.defectdojo import export_scan

    scan = await session.get(ScanRow, scan_id)
    if scan is None:
        raise HTTPException(404, "scan não encontrado")

    try:
        result = await export_scan(scan_id)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"falha ao exportar: {e}") from e

    return JSONResponse(content=result)
