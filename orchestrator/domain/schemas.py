"""Canonical Finding schema and supporting types.

Every scanner adapter must normalize its output into a `Finding`.
Downstream (AIAnalyzer, reporting, dedup, persistence) only knows about Findings.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Quão certo o scanner está do achado. Mapeia ZAP, Nuclei, Greenbone."""

    TENTATIVE = "tentative"
    FIRM = "firm"
    CERTAIN = "certain"


class AssetType(StrEnum):
    HOST = "host"
    URL = "url"
    PORT = "port"
    IMAGE = "image"
    REPO = "repo"
    DOMAIN = "domain"
    K8S_RESOURCE = "k8s_resource"


class Target(BaseModel):
    """Alvo de uma varredura. Aceita formas diferentes (host, URL, imagem, repo)."""

    model_config = ConfigDict(frozen=True)

    asset_type: AssetType
    value: str = Field(description="host:port, URL, nome de imagem, URL de repo, etc.")
    label: str | None = None
    criticality: Severity = Severity.MEDIUM
    contains_pii: bool = Field(
        default=False,
        description="Alvo trata dados pessoais. Hint pra rotear triage ao LLM local.",
    )


class CvssV3(BaseModel):
    """Vetor CVSSv3 mínimo. Calcular score na hora se vier vetor."""

    score: float = Field(ge=0.0, le=10.0)
    vector: str | None = None
    severity: Severity | None = None


class Evidence(BaseModel):
    """Evidência de um achado. Request/response, payload, screenshot ref."""

    description: str
    request: str | None = None
    response: str | None = None
    payload: str | None = None
    snippet: str | None = None
    screenshot_path: str | None = None


class AITriage(BaseModel):
    """Saída do AIAnalyzer para um Finding."""

    adjusted_severity: Severity
    rationale: str
    is_likely_false_positive: bool = False
    business_impact: str | None = None
    suggested_remediation: str | None = None
    suggested_poc: str | None = None
    owasp_top10: str | None = Field(
        default=None,
        description="Categoria OWASP Top 10 (2021), ex: 'A03:2021-Injection'.",
    )
    model_used: str
    triaged_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Finding(BaseModel):
    """Achado canônico — qualquer scanner normaliza para esta forma."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID

    target: Target
    source_tool: str = Field(description="nmap | zap | nuclei | trivy | greenbone | ...")
    source_rule_id: str | None = Field(
        default=None,
        description="ID nativo do scanner (ZAP plugin id, Nuclei template id, OID Greenbone)",
    )

    vuln_id: str | None = Field(default=None, description="CVE-2024-xxxxx, GHSA-xxxx, etc.")
    cwe: list[str] = Field(default_factory=list)

    title: str
    description: str
    severity: Severity
    cvss_v3: CvssV3 | None = None
    confidence: Confidence = Confidence.FIRM

    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str | None = None
    references: list[HttpUrl] = Field(default_factory=list)

    raw_output_ref: str | None = Field(
        default=None,
        description="Caminho no volume reports_out para a saída bruta do scanner",
    )

    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    deduped_key: str = Field(default="")

    ai_triage: AITriage | None = None

    @model_validator(mode="after")
    def _build_dedup_key(self) -> Finding:
        if self.deduped_key:
            return self
        rule_id = self.source_rule_id or self.vuln_id or self.title or ""
        material = f"{self.target.value}::{rule_id}".encode()
        # set via __dict__ to avoid re-triggering validation
        object.__setattr__(self, "deduped_key", hashlib.sha256(material).hexdigest()[:32])
        return self


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELED = "canceled"


class ScanHandle(BaseModel):
    """Identifica uma varredura em andamento dentro de um adapter específico."""

    adapter: str
    native_id: str = Field(description="ID nativo do scanner (ZAP scan id, Greenbone task id)")
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class RawResults(BaseModel):
    """Resultado bruto de um scanner antes da normalização."""

    adapter: str
    payload: Any  # XML string, dict JSON, lista de issues — formato livre por scanner
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
