"""Targets CRUD."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel import select

from orchestrator.api.deps import SessionDep, TokenDep
from orchestrator.domain.schemas import AssetType, Severity
from orchestrator.persistence.models import TargetRow

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetIn(BaseModel):
    asset_type: AssetType
    value: str
    label: str | None = None
    criticality: Severity = Severity.MEDIUM
    contains_pii: bool = False
    metadata: dict = Field(default_factory=dict)


class TargetOut(BaseModel):
    id: UUID
    asset_type: str
    value: str
    label: str | None
    criticality: str
    contains_pii: bool


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(
    body: TargetIn,
    session: SessionDep,
    _token: TokenDep,
) -> TargetOut:
    row = TargetRow(
        asset_type=body.asset_type.value,
        value=body.value,
        label=body.label,
        criticality=body.criticality.value,
        contains_pii=body.contains_pii,
        metadata_json=body.metadata,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return TargetOut(
        id=row.id,
        asset_type=row.asset_type,
        value=row.value,
        label=row.label,
        criticality=row.criticality,
        contains_pii=row.contains_pii,
    )


@router.get("", response_model=list[TargetOut])
async def list_targets(session: SessionDep, _token: TokenDep) -> list[TargetOut]:
    rows = (await session.exec(select(TargetRow))).all()
    return [
        TargetOut(
            id=r.id,
            asset_type=r.asset_type,
            value=r.value,
            label=r.label,
            criticality=r.criticality,
            contains_pii=r.contains_pii,
        )
        for r in rows
    ]


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(target_id: UUID, session: SessionDep, _token: TokenDep) -> TargetOut:
    row = await session.get(TargetRow, target_id)
    if row is None:
        raise HTTPException(404, "target não encontrado")
    return TargetOut(
        id=row.id,
        asset_type=row.asset_type,
        value=row.value,
        label=row.label,
        criticality=row.criticality,
        contains_pii=row.contains_pii,
    )
