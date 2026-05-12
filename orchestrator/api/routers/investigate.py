"""Investigate router — agentic deep-dive em finding individual.

POST /investigate/{finding_id} dispara investigação usando CAI framework / fallback Claude
sob HITL (dry_run=true por padrão).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from orchestrator.api.deps import SessionDep, TokenDep
from orchestrator.persistence.models import FindingRow

router = APIRouter(prefix="/investigate", tags=["investigate"])


class InvestigationIn(BaseModel):
    instructions: str | None = None
    dry_run: bool = True
    max_steps: int = 10


class InvestigationOut(BaseModel):
    finding_id: UUID
    transcript: list[dict]
    final_assessment: str
    dry_run: bool
    trace_url: str | None = None


@router.post("/{finding_id}", response_model=InvestigationOut)
async def investigate(
    finding_id: UUID,
    body: InvestigationIn,
    session: SessionDep,
    _token: TokenDep,
) -> InvestigationOut:
    finding = await session.get(FindingRow, finding_id)
    if finding is None:
        raise HTTPException(404, "finding não encontrado")

    from orchestrator.ai.agentic.cai_expert import investigate_finding

    try:
        result = await investigate_finding(
            finding,
            extra_instructions=body.instructions,
            dry_run=body.dry_run,
            max_steps=body.max_steps,
        )
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"investigação falhou: {e}") from e

    return InvestigationOut(
        finding_id=finding_id,
        transcript=result.get("transcript", []),
        final_assessment=result.get("final_assessment", ""),
        dry_run=body.dry_run,
        trace_url=result.get("trace_url"),
    )
