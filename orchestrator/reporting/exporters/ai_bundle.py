"""AI Fix Bundle exporter — JSON estruturado pra outra IA consumir e patchar código.

Schema versionado em `docs/ai-fix-bundle-spec.md`. Patcher externo
(Claude Code, Cursor, Copilot) recebe esse JSON e produz patches.

Determinístico: mesmo scan_id → mesmo bundle (modulo timestamps).
`vulnerabilities[].id` é uuid5(deduped_key) — estável entre runs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid5

import structlog
from sqlmodel import select

from orchestrator.domain.scrubber import scrub
from orchestrator.persistence.db import session
from orchestrator.persistence.models import FindingRow, ScanRow, TargetRow

log = structlog.get_logger(__name__)

SCHEMA_VERSION = "1.0.0"

# UUID namespace estável pra derivar IDs determinísticos a partir do deduped_key.
_BUNDLE_UUID_NS = UUID("d4a3f8c9-1e2b-4a5c-9b3d-7c8e6f5a2b1c")

# Mapa adapter → categoria pro patcher entender o tipo de fix
_CATEGORY_BY_TOOL: dict[str, str] = {
    "nmap": "infra",
    "zap": "web",
    "nuclei": "web",
    "trivy": "deps",
    "greenbone": "infra",
    "gitleaks": "secret",
    "trufflehog": "secret",
    "github_exposure": "osint",
    "dnstwist": "osint",
    "shodan": "osint",
    "censys": "osint",
    "subdomain_takeover": "osint",
    "checkov": "misconfig",
    "kube_bench": "k8s",
}

_LOCATION_KIND_BY_CATEGORY: dict[str, str] = {
    "web": "http_endpoint",
    "infra": "host_port",
    "deps": "container_layer",
    "secret": "repo_path",
    "osint": "domain",
    "misconfig": "file_path",
    "k8s": "k8s_resource",
}

_DEFAULT_APPROACH_BY_CATEGORY: dict[str, str] = {
    "web": "code_change",
    "infra": "config_change",
    "deps": "dependency_upgrade",
    "secret": "secret_rotation",
    "osint": "manual",
    "misconfig": "config_change",
    "k8s": "config_change",
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def build_bundle(scan_id: UUID) -> dict[str, Any]:
    """Gera o AI Fix Bundle completo pra um scan_id."""

    async with session() as s:
        scan = await s.get(ScanRow, scan_id)
        if scan is None:
            raise ValueError(f"scan {scan_id} não encontrado")

        target = await s.get(TargetRow, scan.target_id)
        rows = (await s.exec(select(FindingRow).where(FindingRow.scan_id == scan_id))).all()

    log.info("bundle.build_start", scan_id=str(scan_id), findings=len(rows))

    vulnerabilities = [_finding_to_vuln(r) for r in rows]
    # ordenar por patch_priority (1 = urgente)
    vulnerabilities.sort(key=lambda v: v["patch_priority"])

    bundle = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "generator": {
            "tool": "cai",
            "version": "0.3.0",
            "model_used": _detect_model_used(rows),
        },
        "scan": {
            "id": str(scan_id),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "scanners_executed": list(scan.requested_scanners or []),
            "scanners_failed": [e.split(":")[0] for e in (scan.errors or []) if ":" in e],
        },
        "target": _target_section(target),
        "summary": _summary(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "appendix": {
            "raw_scan_artifacts": [
                {"tool": r.source_tool, "path": str(scan.report_path)}
                for r in rows[:1]
                if scan.report_path
            ],
            "scrubbing_applied": [
                "cpf",
                "cnpj",
                "pan_luhn",
                "cvv",
                "email",
                "jwt",
                "aws_keys",
                "auth_header",
                "phone_br",
            ],
            "patcher_instructions": (
                "Process vulnerabilities in patch_priority order. For each, run "
                "code_search_patterns against the repo, propose a patch following "
                "before_after_examples. Use verification.rerun to confirm fix."
            ),
        },
    }

    log.info("bundle.build_done", scan_id=str(scan_id), vulns=len(vulnerabilities))
    return bundle


def _detect_model_used(rows: list[FindingRow]) -> str | None:
    for r in rows:
        triage = (r.payload or {}).get("ai_triage")
        if isinstance(triage, dict) and triage.get("model_used"):
            return triage["model_used"]
    return None


def _target_section(target: TargetRow | None) -> dict[str, Any]:
    if target is None:
        return {
            "primary_value": "unknown",
            "asset_type": "unknown",
            "scope": [],
            "out_of_scope": [],
            "tech_stack_hints": _empty_tech_stack(),
            "source_code_available_to_patcher": False,
        }
    return {
        "primary_value": target.value,
        "asset_type": target.asset_type,
        "label": target.label,
        "scope": [target.value],
        "out_of_scope": [],
        "contains_pii": target.contains_pii,
        "tech_stack_hints": _empty_tech_stack(),  # TODO: derivar de evidências (Fase 2.5)
        "source_code_available_to_patcher": False,
    }


def _empty_tech_stack() -> dict[str, Any]:
    return {
        "languages": [],
        "frameworks": [],
        "runtimes": [],
        "servers": [],
        "package_managers": [],
        "source_repos": [],
        "container_images": [],
        "confidence": "low",
    }


def _summary(vulns: list[dict[str, Any]]) -> dict[str, Any]:
    counts_sev: dict[str, int] = {s: 0 for s in _SEVERITY_RANK}
    counts_cat: dict[str, int] = {}
    owasp_set: set[str] = set()
    cwe_count: dict[str, int] = {}
    auto_count = 0
    review_count = 0

    for v in vulns:
        counts_sev[v["severity"]] = counts_sev.get(v["severity"], 0) + 1
        counts_cat[v["category"]] = counts_cat.get(v["category"], 0) + 1
        owasp = v["classification"].get("owasp_top10_2021")
        if owasp:
            # extrair só "A03" do "A03:2021-Injection"
            owasp_set.add(owasp.split(":")[0])
        for cwe in v["classification"].get("cwe", []):
            cwe_count[cwe] = cwe_count.get(cwe, 0) + 1
        confidence = v["remediation"]["patch_strategy"]["confidence"]
        if confidence == "high":
            auto_count += 1
        else:
            review_count += 1

    top_cwes = sorted(cwe_count.items(), key=lambda kv: -kv[1])[:5]

    return {
        "counts_by_severity": counts_sev,
        "counts_by_category": counts_cat,
        "owasp_top10_2021": sorted(owasp_set),
        "top_cwes": [c for c, _ in top_cwes],
        "patchable_automatically_count": auto_count,
        "needs_human_review_count": review_count,
    }


def _finding_to_vuln(row: FindingRow) -> dict[str, Any]:
    """Converte um FindingRow do DB num bloco vulnerability do bundle."""
    payload = row.payload or {}
    triage = payload.get("ai_triage") or {}
    cwe = list(payload.get("cwe") or [])

    category = _CATEGORY_BY_TOOL.get(row.source_tool, "infra")
    location_kind = _LOCATION_KIND_BY_CATEGORY.get(category, "host_port")
    approach = _DEFAULT_APPROACH_BY_CATEGORY.get(category, "code_change")
    sev_rank = _SEVERITY_RANK.get(row.severity, 9)

    # uuid estável: namespace + deduped_key
    vuln_id = str(uuid5(_BUNDLE_UUID_NS, row.deduped_key))

    target_obj = payload.get("target") or {}
    target_value = target_obj.get("value") or row.title

    # evidence — passa pelo scrubber antes de servir
    evidence_list = payload.get("evidence") or []
    instances = []
    for ev in evidence_list[:3]:  # máximo 3 evidências por vuln
        instances.append(
            {
                "instance_id": str(uuid5(_BUNDLE_UUID_NS, row.deduped_key + str(ev))),
                "location": _build_location(location_kind, target_value, payload),
                "evidence": _scrub_evidence(ev),
            }
        )

    if not instances:
        # fallback: instância vazia mas com location preenchida
        instances.append(
            {
                "instance_id": str(uuid5(_BUNDLE_UUID_NS, row.deduped_key + "_default")),
                "location": _build_location(location_kind, target_value, payload),
                "evidence": {
                    "scrubbed": True,
                    "description": scrub(payload.get("description", "")),
                },
            }
        )

    return {
        "id": vuln_id,
        "deduped_key": row.deduped_key,
        "title": row.title,
        "category": category,
        "severity": row.severity,
        "severity_original": payload.get("severity", row.severity),
        "confidence": row.confidence,
        "patch_priority": _patch_priority(sev_rank, row.confidence),
        "classification": {
            "owasp_top10_2021": triage.get("owasp_top10"),
            "cwe": cwe,
            "cve": row.vuln_id if row.vuln_id and row.vuln_id.upper().startswith("CVE-") else None,
            "ghsa": row.vuln_id if row.vuln_id and row.vuln_id.upper().startswith("GHSA") else None,
            "cvss_v3": payload.get("cvss_v3"),
            "epss_percentile": None,
            "exploit_available": False,
        },
        "discovered_by": {
            "tool": row.source_tool,
            "rule_id": row.source_rule_id,
            "rule_name": row.title,
            "raw_output_ref": payload.get("raw_output_ref"),
        },
        "instances": instances,
        "remediation": _build_remediation(category, approach, triage, payload),
        "verification": _build_verification(row.source_tool, target_value),
        "ai_triage": {
            "rationale": triage.get("rationale"),
            "is_likely_false_positive": bool(triage.get("is_likely_false_positive", False)),
            "business_impact": triage.get("business_impact"),
            "model_used": triage.get("model_used"),
        }
        if triage
        else None,
    }


def _patch_priority(sev_rank: int, confidence: str) -> int:
    """1=urgente, 5=cosmético. Combina severity + confidence."""
    base = sev_rank + 1  # critical=1, high=2, medium=3, low=4, info=5
    if confidence == "tentative":
        base = min(base + 1, 5)
    return base


def _build_location(kind: str, target_value: str, payload: dict[str, Any]) -> dict[str, Any]:
    base = {"kind": kind}
    if kind == "http_endpoint":
        parsed = urlparse(target_value) if "://" in target_value else None
        base.update(
            {
                "url": target_value,
                "method": "GET",
                "parameter": None,
                "parameter_location": None,
                "request_template": None,
                "host": parsed.hostname if parsed else None,
            }
        )
    elif kind == "host_port":
        host = target_value.split(":")[0]
        port = target_value.split(":")[1] if ":" in target_value else None
        base.update({"host": host, "port": port, "protocol": None})
    elif kind == "repo_path":
        base.update({"path": target_value, "line": None})
    elif kind == "domain":
        base.update({"domain": target_value})
    elif kind == "file_path":
        base.update({"path": target_value, "line": None})
    elif kind == "container_layer":
        base.update({"image": target_value, "package": None, "version": None})
    elif kind == "k8s_resource":
        base.update({"resource_id": target_value})
    return base


def _scrub_evidence(ev: dict[str, Any]) -> dict[str, Any]:
    """Aplica scrubber nos campos de evidência. Trunca payloads enormes."""
    return {
        "scrubbed": True,
        "description": scrub(ev.get("description", ""))[:500],
        "request_sent": scrub(ev.get("request") or "")[:2000] if ev.get("request") else None,
        "response_received_excerpt": (
            scrub(ev.get("response") or "")[:2000] if ev.get("response") else None
        ),
        "payload_used": scrub(ev.get("payload") or "") if ev.get("payload") else None,
        "snippet": scrub(ev.get("snippet") or "") if ev.get("snippet") else None,
    }


def _build_remediation(
    category: str,
    approach: str,
    triage: dict[str, Any],
    payload: dict[str, Any],
) -> dict[str, Any]:
    summary = triage.get("suggested_remediation") or payload.get("remediation") or ""
    return {
        "summary": summary,
        "rationale": triage.get("rationale", ""),
        "patch_strategy": {
            "approach": approach,
            "confidence": "high"
            if approach in ("dependency_upgrade", "config_change")
            else "medium",
            "estimated_effort": "small" if approach == "config_change" else "medium",
            "blast_radius": "module" if approach == "code_change" else "service",
        },
        "code_search_patterns": [],  # populado por agent fix-bundle-author quando enrich_with_ai=True
        "before_after_examples": [],
        "dependency_upgrade": None,
        "config_change": None,
        "secret_rotation": (
            {"credential_type": "unknown", "scope": "unknown", "rotation_steps": []}
            if approach == "secret_rotation"
            else None
        ),
        "references": list(payload.get("references") or []),
    }


def _build_verification(tool: str, target_value: str) -> dict[str, Any]:
    return {
        "method": "rerun_scanner",
        "rerun": {
            "scanner": tool,
            "scan_profile": "focused",
            "options": {"target": target_value},
            "expected_outcome": f"no {tool} alert for this rule on this target",
        },
        "http_probe": None,
        "suggested_unit_tests": [],
    }
