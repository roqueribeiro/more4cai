"""Pipeline OSINT/Exposure externa (Fase 2.5).

Chama: GitHubExposureAdapter, GitleaksAdapter (em cima dos repos descobertos),
TrufflehogAdapter, DnstwistAdapter, ShodanAdapter, SubdomainTakeoverAdapter.

Read-only sobre dados públicos.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import structlog

from orchestrator.adapters.dnstwist_adapter import DnstwistAdapter
from orchestrator.adapters.github_exposure_adapter import GitHubExposureAdapter
from orchestrator.adapters.gitleaks_adapter import GitleaksAdapter
from orchestrator.adapters.shodan_adapter import ShodanAdapter
from orchestrator.adapters.subdomain_takeover_adapter import SubdomainTakeoverAdapter
from orchestrator.adapters.trufflehog_adapter import TrufflehogAdapter
from orchestrator.ai.analyzer import triage_batch
from orchestrator.config import settings
from orchestrator.domain.schemas import AssetType, Finding, Target
from orchestrator.jobs.pipelines import ScanResult, _run_adapter
from orchestrator.reporting.renderer import render_html

log = structlog.get_logger(__name__)


async def run_exposure_scan(
    *,
    company_name: str,
    domains: list[str],
    github_orgs: list[str],
    dorks: list[str],
    skip_ai: bool = False,
    deep_secrets_in_top_repos: int = 5,
) -> ScanResult:
    """Pipeline OSINT — não toca em ativos do banco, só dados públicos.

    1. GitHubExposure: roda dorks contra org/strings sensíveis → repos suspeitos.
    2. GitleaksAdapter + TrufflehogAdapter nos top-N repos descobertos.
    3. DnstwistAdapter em cada domínio do banco.
    4. ShodanAdapter (opt-in via SHODAN_API_KEY).
    5. SubdomainTakeoverAdapter em cada domínio.
    """

    scan_id = uuid4()
    company_target = Target(asset_type=AssetType.DOMAIN, value=company_name)
    result = ScanResult(scan_id=scan_id, target=company_target)

    # 1. GitHub dorks
    gh = GitHubExposureAdapter()
    if await gh.health() and dorks:
        try:
            github_findings = await _run_adapter(
                gh, company_target, options={"dorks": dorks, "max_results_per_dork": 30}
            )
            for f in github_findings:
                f.scan_id = scan_id
            result.findings.extend(github_findings)

            # 2. Top-N repos descobertos → gitleaks + trufflehog
            top_repos = list({f.target.value for f in github_findings})[:deep_secrets_in_top_repos]
            for repo_url in top_repos:
                repo_target = Target(asset_type=AssetType.REPO, value=repo_url)
                for adapter in (GitleaksAdapter(), TrufflehogAdapter()):
                    if await adapter.health():
                        try:
                            secrets_findings = await _run_adapter(adapter, repo_target, options={})
                            for f in secrets_findings:
                                f.scan_id = scan_id
                            result.findings.extend(secrets_findings)
                        except Exception as e:  # noqa: BLE001
                            log.exception("exposure.secret_adapter_failed", error=str(e))
                            result.errors.append(f"{adapter.name}@{repo_url}: {e}")
        except Exception as e:  # noqa: BLE001
            log.exception("exposure.github_failed", error=str(e))
            result.errors.append(f"github_exposure: {e}")
    elif dorks:
        result.errors.append("github_exposure: GITHUB_TOKEN ausente — pulei dorks")

    # 3. dnstwist por domínio
    dt = DnstwistAdapter()
    if await dt.health():
        for d in domains:
            try:
                dn_target = Target(asset_type=AssetType.DOMAIN, value=d)
                dn_findings = await _run_adapter(dt, dn_target, options={})
                for f in dn_findings:
                    f.scan_id = scan_id
                result.findings.extend(dn_findings)
            except Exception as e:  # noqa: BLE001
                result.errors.append(f"dnstwist@{d}: {e}")
    else:
        result.errors.append("dnstwist: binário não disponível")

    # 4. Shodan (opt-in)
    sh = ShodanAdapter()
    if await sh.health():
        try:
            sh_findings = await _run_adapter(
                sh,
                company_target,
                options={"query": f'org:"{company_name}"', "limit": 100},
            )
            for f in sh_findings:
                f.scan_id = scan_id
            result.findings.extend(sh_findings)
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"shodan: {e}")

    # 5. Subdomain takeover por domínio (paralelo)
    st = SubdomainTakeoverAdapter()
    if await st.health() and domains:
        coros = []
        for d in domains:
            dn_target = Target(asset_type=AssetType.DOMAIN, value=d)
            coros.append(_run_adapter(st, dn_target, options={}))
        try:
            results_list = await asyncio.gather(*coros, return_exceptions=True)
            for r in results_list:
                if isinstance(r, Exception):
                    result.errors.append(f"subdomain_takeover: {r}")
                    continue
                for f in r:
                    f.scan_id = scan_id
                result.findings.extend(r)
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"subdomain_takeover: {e}")

    # AI triage
    if not skip_ai and result.findings:
        try:
            await triage_batch(result.findings)
        except Exception as e:  # noqa: BLE001
            log.exception("exposure.triage_failed", error=str(e))
            result.errors.append(f"ai_triage: {e}")

    # Relatório
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = settings.REPORTS_DIR / f"exposure-{scan_id}.html"
    render_html(result, report_path)
    result.report_path = report_path

    log.info(
        "exposure.complete",
        scan_id=str(scan_id),
        findings=len(result.findings),
        errors=result.errors,
    )

    # cleanup
    if hasattr(gh, "_client") and gh._client:  # noqa: SLF001
        pass  # PyGithub não tem aclose

    return result
