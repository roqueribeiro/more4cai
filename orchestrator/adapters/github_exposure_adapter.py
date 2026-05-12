"""GitHub exposure — busca por código e secrets em repos públicos via GitHub Search.

Não é um scanner com lifecycle típico — é mais uma "consulta + materializa findings".
Mantém a interface ScannerAdapter pra integrar no pipeline.
"""

from __future__ import annotations

import os
from typing import Any
from uuid import uuid4

import structlog
from github import Github
from github.GithubException import GithubException, RateLimitExceededException

from orchestrator.domain.schemas import (
    AssetType,
    Confidence,
    Evidence,
    Finding,
    RawResults,
    ScanHandle,
    ScanStatus,
    Severity,
    Target,
)

log = structlog.get_logger(__name__)


class GitHubExposureAdapter:
    """Roda buscas com dorks contra a API do GitHub.

    Target.value = nome da org/banco. Options['dorks'] = lista de queries.
    Ex: dorks=["bancoexemplo password", "bancoexemplo.com.br api_key"]
    """

    name = "github_exposure"

    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self._client: Github | None = None
        self._scans: dict[str, dict[str, Any]] = {}

    def _gh(self) -> Github:
        if self._client is None:
            if not self.token:
                raise RuntimeError("GITHUB_TOKEN não configurado")
            self._client = Github(self.token, per_page=30)
        return self._client

    async def health(self) -> bool:
        if not self.token:
            return False
        try:
            user = self._gh().get_user()
            _ = user.login  # força round-trip
            return True
        except (GithubException, RuntimeError) as e:
            log.warning("github.health_failed", error=str(e))
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        # Execução síncrona com a API do GitHub (rate-limited).
        # Pra fase 2.5, segue ok; pode mover pra worker arq depois.
        dorks = options.get("dorks") or [target.value]
        max_results_per_dork = int(options.get("max_results_per_dork", 30))

        results: list[dict[str, Any]] = []
        gh = self._gh()
        for dork in dorks:
            try:
                code = gh.search_code(dork)
                count = 0
                for item in code:
                    if count >= max_results_per_dork:
                        break
                    results.append(
                        {
                            "dork": dork,
                            "repo": item.repository.full_name,
                            "repo_url": item.repository.html_url,
                            "path": item.path,
                            "url": item.html_url,
                            "sha": item.sha,
                        }
                    )
                    count += 1
            except RateLimitExceededException:
                log.warning("github.rate_limit", dork=dork)
                break
            except GithubException as e:
                log.error("github.search_failed", dork=dork, error=str(e))

        native_id = str(uuid4())
        self._scans[native_id] = {"results": results, "target": target.value, "dorks": dorks}

        return ScanHandle(
            adapter=self.name,
            native_id=native_id,
            metadata={"company": target.value, "dorks": dorks, "results": len(results)},
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        # síncrono: já está pronto após start_scan
        return ScanStatus.DONE if handle.native_id in self._scans else ScanStatus.FAILED

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        return RawResults(adapter=self.name, payload=self._scans[handle.native_id])

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()

        company = raw.payload.get("target", "")
        for item in raw.payload.get("results", []):
            target = Target(asset_type=AssetType.REPO, value=item["repo_url"])
            findings.append(
                Finding(
                    scan_id=placeholder,
                    target=target,
                    source_tool=self.name,
                    source_rule_id=f"dork-{item['dork']}",
                    title=f"Match de dork '{item['dork']}' em {item['repo']}",
                    description=(
                        f"Repo público {item['repo']} contém arquivo {item['path']} "
                        f"que casa com a busca '{item['dork']}'. "
                        f"Empresa de referência: {company}. Investigar se é vazamento real."
                    ),
                    severity=Severity.MEDIUM,  # AI vai promover/rebaixar
                    confidence=Confidence.TENTATIVE,
                    evidence=[
                        Evidence(
                            description=f"dork={item['dork']} repo={item['repo']} path={item['path']}",
                            snippet=item.get("url"),
                        )
                    ],
                )
            )
        log.info("github_exposure.normalize_done", findings=len(findings))
        return findings
