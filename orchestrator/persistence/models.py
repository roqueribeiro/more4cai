"""Persistence models (SQLModel) — Target, Scan, FindingRow, AIRun."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime
from sqlmodel import Field, SQLModel

from orchestrator.domain.schemas import Severity


class ScanState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELED = "canceled"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TargetRow(SQLModel, table=True):
    __tablename__ = "targets"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    asset_type: str
    value: str = Field(index=True)
    label: str | None = None
    criticality: str = Severity.MEDIUM.value
    contains_pii: bool = False
    metadata_json: dict[str, Any] = Field(default_factory=dict, sa_type=JSON)
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))


class ScanRow(SQLModel, table=True):
    __tablename__ = "scans"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    target_id: UUID = Field(foreign_key="targets.id", index=True)
    state: str = Field(default=ScanState.PENDING.value, index=True)
    profile: str = "web"  # web | network | exposure | cloud | full
    requested_scanners: list[str] = Field(default_factory=list, sa_type=JSON)
    options: dict[str, Any] = Field(default_factory=dict, sa_type=JSON)
    actor: str | None = None
    started_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    finished_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    errors: list[str] = Field(default_factory=list, sa_type=JSON)
    report_path: str | None = None
    # Granularidade de fase: queued|nmap_running|zap_spider|zap_passive|zap_active|
    # dedup|ai_triage|persisting|reporting|done|failed
    current_phase: str | None = Field(default=None, index=True)
    phase_progress: int | None = None  # 0-100 quando aplicável (ex: ZAP spider %)
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))


class FindingRow(SQLModel, table=True):
    __tablename__ = "findings"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_id: UUID = Field(foreign_key="scans.id", index=True)
    target_id: UUID = Field(foreign_key="targets.id", index=True)
    deduped_key: str = Field(index=True)
    source_tool: str = Field(index=True)
    source_rule_id: str | None = None
    vuln_id: str | None = Field(default=None, index=True)
    title: str
    severity: str = Field(index=True)
    confidence: str = "firm"
    payload: dict[str, Any] = Field(default_factory=dict, sa_type=JSON)
    discovered_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))


class AIRun(SQLModel, table=True):
    """Telemetria de cada chamada LLM — custo, latência, tokens, cache hit."""

    __tablename__ = "ai_runs"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_id: UUID | None = Field(default=None, foreign_key="scans.id", index=True)
    purpose: str  # "triage" | "investigation" | "report_narrative"
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    latency_ms: int = 0
    estimated_cost_usd: float = 0.0
    finding_count: int = 0
    success: bool = True
    error: str | None = None
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
