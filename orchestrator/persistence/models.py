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


class FindingStatus(StrEnum):
    """Estado de RESOLUÇÃO de um problema (workflow), ortogonal à severity.

    Atrelado ao `deduped_key` (identidade determinística do problema), não a um
    FindingRow (instância de um scan) — ver `FindingStatusRow`.
    """

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    RISK_ACCEPTED = "risk_accepted"


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
    # Referência formal à autorização (ticket, change, aprovação por escrito).
    # Exigido quando settings.REQUIRE_AUTH_REF=true.
    authorization_ref: str | None = Field(default=None, index=True)
    started_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    finished_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    errors: list[str] = Field(default_factory=list, sa_type=JSON)
    report_path: str | None = None
    # Granularidade de fase: queued|nmap_running|zap_spider|zap_passive|zap_active|
    # dedup|ai_triage|persisting|reporting|done|failed
    current_phase: str | None = Field(default=None, index=True)
    phase_progress: int | None = None  # 0-100 quando aplicável (ex: ZAP spider %)
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))


class AuditLogRow(SQLModel, table=True):
    """Audit log append-only.

    Em Postgres, UPDATE/DELETE são rejeitados pelo trigger `audit_log_no_update`
    instalado pela migration 0004. Em SQLite (dev), o trigger não existe — o
    contrato é mantido apenas no código (`orchestrator.audit.logger`).
    """

    __tablename__ = "audit_log"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    actor: str | None = Field(default=None, index=True)
    action: str = Field(index=True)  # ex: "scan.create", "target.create"
    resource_type: str | None = None  # ex: "scan", "target"
    resource_id: UUID | None = Field(default=None, index=True)
    authorization_ref: str | None = Field(default=None, index=True)
    request_hash: str | None = None  # sha256 do body da requisição (sem PII)
    metadata_json: dict[str, Any] = Field(default_factory=dict, sa_type=JSON)
    created_at: datetime = Field(
        default_factory=_utcnow, sa_type=DateTime(timezone=True), index=True
    )


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


class FindingStatusRow(SQLModel, table=True):
    """Estado de resolução (triage de workflow) de um problema único.

    Keyed por `deduped_key` (a IDENTIDADE determinística do problema — ver
    `Finding._build_dedup_key`), NÃO por finding id. Razão: `findings` é
    write-once e um re-scan cria novos FindingRow com o MESMO `deduped_key`;
    o estado "resolvido/aceito/falso-positivo" pertence ao PROBLEMA, então
    precisa sobreviver entre scans. Quem corrige um problema no código-alvo e
    re-escaneia continua vendo "resolvido" (e se o problema sumir do re-scan,
    fica confirmado). Toda mudança aqui também gera entrada no `audit_log`
    (ver `api/routers/findings.py::resolve_finding`).

    `last_*`/`target_value` são um snapshot denormalizado do último finding
    visto com essa key — dá contexto na listagem/auditoria sem JOIN e mesmo se
    o FindingRow for podado.
    """

    __tablename__ = "finding_status"

    deduped_key: str = Field(primary_key=True)
    status: str = Field(default=FindingStatus.OPEN.value, index=True)
    note: str | None = None
    updated_by: str | None = Field(default=None, index=True)
    updated_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    resolved_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    # snapshot denormalizado do último finding com essa key (contexto sem JOIN)
    last_severity: str | None = Field(default=None, index=True)
    last_title: str | None = None
    target_value: str | None = Field(default=None, index=True)


class UserRow(SQLModel, table=True):
    """Usuário nomeado + papel (RBAC).

    Auth por **token por-usuário** (hash SHA-256 — o token em claro só aparece
    UMA vez, na criação/rotação). `idp_subject` reservado pro login OIDC/SSO
    (Fase 6). O `APP_TOKEN` global continua válido como principal de serviço
    (admin) — ver `orchestrator.api.deps`.
    """

    __tablename__ = "users"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(index=True, unique=True)
    name: str | None = None
    role: str = Field(default="viewer", index=True)  # admin|operator|auditor|viewer
    # SHA-256 do token por-usuário (nunca guardamos o token em claro).
    api_token_hash: str | None = Field(default=None, index=True, unique=True)
    idp_subject: str | None = Field(default=None, index=True)  # OIDC `sub` (Fase 6)
    active: bool = Field(default=True, index=True)
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    last_login_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


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
