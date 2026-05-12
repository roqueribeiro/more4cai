"""Censys adapter — alternativa ao Shodan pra exposição de internet.

Requer pacote `censys` opcional. Opt-in.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any
from uuid import uuid4

import structlog

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


class CensysAdapter:
    name = "censys"

    def __init__(self, api_id: str | None = None, api_secret: str | None = None) -> None:
        self.api_id = api_id or os.environ.get("CENSYS_API_ID", "")
        self.api_secret = api_secret or os.environ.get("CENSYS_API_SECRET", "")
        self._scans: dict[str, dict[str, Any]] = {}

    async def health(self) -> bool:
        if not (self.api_id and self.api_secret):
            return False
        try:
            from censys.search import CensysHosts  # type: ignore[import-not-found]

            CensysHosts(api_id=self.api_id, api_secret=self.api_secret)
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("censys.health_failed", error=str(e))
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        from censys.search import CensysHosts  # type: ignore[import-not-found]

        query = options.get("query") or target.value
        hosts = CensysHosts(api_id=self.api_id, api_secret=self.api_secret)

        def _run() -> list[dict[str, Any]]:
            results: list[dict[str, Any]] = []
            try:
                for page in hosts.search(query, per_page=100, pages=int(options.get("pages", 1))):
                    results.extend(page)
            except Exception as e:  # noqa: BLE001
                log.error("censys.search_failed", error=str(e))
            return results

        results = await asyncio.to_thread(_run)
        native_id = str(uuid4())
        self._scans[native_id] = {"query": query, "results": results}
        return ScanHandle(
            adapter=self.name,
            native_id=native_id,
            metadata={"query": query, "count": len(results)},
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        return ScanStatus.DONE if handle.native_id in self._scans else ScanStatus.FAILED

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        return RawResults(adapter=self.name, payload=self._scans[handle.native_id])

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()
        for h in raw.payload.get("results", []):
            ip = h.get("ip", "?")
            services = h.get("services") or []
            for svc in services:
                port = svc.get("port", "?")
                proto = svc.get("transport_protocol", "tcp").lower()
                target_obj = Target(
                    asset_type=AssetType.HOST,
                    value=f"{ip}:{port}/{proto}",
                    label=svc.get("service_name", "unknown"),
                )
                findings.append(
                    Finding(
                        scan_id=placeholder,
                        target=target_obj,
                        source_tool=self.name,
                        source_rule_id=svc.get("service_name", "unknown"),
                        title=f"Censys exposure: {svc.get('service_name')} em {ip}:{port}",
                        description=(
                            f"Serviço {svc.get('service_name')} em {ip}:{port}/{proto}. "
                            f"Software: {svc.get('software', [])}"
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        evidence=[Evidence(description=f"banner em port {port}")],
                    )
                )
        log.info("censys.normalize_done", findings=len(findings))
        return findings
