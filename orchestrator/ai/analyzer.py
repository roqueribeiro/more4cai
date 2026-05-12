"""AIAnalyzer — triagem contextual de Findings com LLM.

Recebe lote de Findings, devolve lote de AITriage (1:1).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from orchestrator.ai.gateway import complete_json
from orchestrator.config import settings
from orchestrator.domain.schemas import AITriage, Finding, Severity
from orchestrator.domain.scrubber import scrub

log = structlog.get_logger(__name__)

PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load_system_prompt() -> str:
    return (PROMPTS_DIR / "system_pentester.md").read_text(encoding="utf-8")


_TRIAGE_INSTRUCTIONS = """\
Você receberá uma LISTA DE FINDINGS em JSON. Retorne JSON estrito no formato:

{
  "triages": [
    {
      "finding_id": "<uuid>",
      "adjusted_severity": "info|low|medium|high|critical",
      "rationale": "explicação curta em PT-BR",
      "is_likely_false_positive": false,
      "business_impact": "impacto técnico/operacional resumido",
      "suggested_remediation": "passos práticos de correção",
      "suggested_poc": "como reproduzir (curl/burp/payload), opcional",
      "owasp_top10": "A03:2021-Injection"
    }
  ]
}

Regras:
- Retorne UMA entrada por finding, na mesma ordem.
- finding_id deve bater com o do input.
- Não invente CVEs. Se não souber, omita.
- Se o finding parece falso positivo claro, marque is_likely_false_positive=true E ajuste severity pra "info".
- owasp_top10 quando aplicável (web/API). Para infra/CVE/secret, pode ser null.
- Justificativa curta e objetiva — sem floreios. Pentester recebe relatório, não palestra.
"""


def _finding_to_compact(f: Finding) -> dict[str, Any]:
    """Versão compacta do finding pro prompt — economiza tokens.

    Aplica `scrub()` em campos free-text (description, evidence) que tipicamente
    carregam dados sensíveis vindos dos scanners (Bearer tokens em headers ZAP,
    PAN em respostas Trivy, emails em achados Trufflehog/Gitleaks). target.value
    pode ser uma URL real do escopo do engagement — preservamos. LGPD Art. 46
    e PCI DSS Req. 3.
    """
    return {
        "finding_id": str(f.id),
        "tool": f.source_tool,
        "rule_id": f.source_rule_id,
        "vuln_id": f.vuln_id,
        "cwe": f.cwe,
        "title": scrub(f.title),
        "description": scrub(f.description[:600]),
        "severity": f.severity,
        "confidence": f.confidence,
        "target": {
            "asset_type": f.target.asset_type,
            "value": f.target.value,
            "criticality": f.target.criticality,
            "contains_pii": f.target.contains_pii,
        },
        "evidence_snippets": [scrub(e.snippet or e.description[:200]) for e in f.evidence[:3]],
    }


_TRIAGE_BATCH_SIZE = 6
_TRIAGE_MAX_TOKENS = 8192
_SKIPPABLE_SEVERITIES_DEFAULT = {Severity.INFO}


async def triage_batch(
    findings: list[Finding],
    *,
    model: str | None = None,
    batch_size: int = _TRIAGE_BATCH_SIZE,
    skip_severities: set[Severity] | None = None,
    scan_id: Any = None,
) -> list[Finding]:
    """Adiciona AITriage a cada Finding. Modifica e devolve a lista.

    Por default pula severity=info (ruído, alto custo de triage). Configurável via
    `skip_severities=set()` se quiser tratar tudo. Divide em batches de `batch_size`
    pra caber no context window de modelos locais (LM Studio default ~50k, Qwen 27B
    com prompt + 25 findings ≈ 6-8k tokens).
    """

    if not findings:
        return findings

    skip = _SKIPPABLE_SEVERITIES_DEFAULT if skip_severities is None else skip_severities
    eligible = [f for f in findings if f.severity not in skip]
    skipped = len(findings) - len(eligible)

    used_model = model or settings.LLM_MODEL
    log.info(
        "ai.triage_start",
        total=len(findings),
        eligible=len(eligible),
        skipped=skipped,
        batch_size=batch_size,
        model=used_model,
    )

    if not eligible:
        log.warning(
            "ai.triage_skipped_no_eligible",
            total=len(findings),
            reason="all findings have severity in skip_severities",
        )
        return findings

    system = _load_system_prompt()
    triages_by_id: dict[str, dict[str, Any]] = {}

    for i in range(0, len(eligible), batch_size):
        batch = eligible[i : i + batch_size]
        log.info("ai.triage_batch", batch=i // batch_size + 1, size=len(batch))
        try:
            user = (
                _TRIAGE_INSTRUCTIONS
                + "\n\nFINDINGS:\n"
                + json.dumps([_finding_to_compact(f) for f in batch], ensure_ascii=False)
            )
            response = await complete_json(
                [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                model=used_model,
                cache_system=True,
                max_tokens=_TRIAGE_MAX_TOKENS,
                purpose="triage",
                scan_id=scan_id,
                finding_count=len(batch),
            )
        except Exception as e:  # noqa: BLE001
            log.error("ai.triage_batch_failed", batch=i // batch_size + 1, error=str(e))
            continue

        for t in response.get("triages", []):
            fid = t.get("finding_id")
            if fid:
                triages_by_id[fid] = t

    for f in eligible:
        t = triages_by_id.get(str(f.id))
        if t is None:
            log.warning("ai.triage_missing", finding_id=str(f.id))
            continue
        try:
            f.ai_triage = AITriage(
                adjusted_severity=Severity(t.get("adjusted_severity", f.severity)),
                rationale=t.get("rationale", ""),
                is_likely_false_positive=bool(t.get("is_likely_false_positive", False)),
                business_impact=t.get("business_impact"),
                suggested_remediation=t.get("suggested_remediation"),
                suggested_poc=t.get("suggested_poc"),
                owasp_top10=t.get("owasp_top10"),
                model_used=used_model,
            )
        except (ValueError, KeyError) as e:
            log.error("ai.triage_parse_failed", finding_id=str(f.id), error=str(e))

    log.info(
        "ai.triage_done",
        triaged=sum(1 for f in findings if f.ai_triage is not None),
        skipped=skipped,
    )
    return findings
