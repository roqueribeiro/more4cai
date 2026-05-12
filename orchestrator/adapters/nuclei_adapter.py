"""Nuclei adapter — runs ProjectDiscovery's nuclei as subprocess, parses JSONL output."""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
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


_NUCLEI_SEVERITY: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.LOW,
}


class NucleiAdapter:
    """Roda nuclei como subprocess. Output JSONL parseado para Findings."""

    name = "nuclei"

    def __init__(
        self,
        nuclei_bin: str | None = None,
        templates_dir: str | None = None,
    ) -> None:
        self.nuclei_bin = nuclei_bin or shutil.which("nuclei") or "nuclei"
        self.templates_dir = templates_dir
        self._tasks: dict[str, asyncio.Task[int]] = {}
        self._output_paths: dict[str, Path] = {}

    async def health(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nuclei_bin,
                "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except (FileNotFoundError, PermissionError):
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        if target.asset_type not in (AssetType.URL, AssetType.HOST, AssetType.DOMAIN):
            raise ValueError(f"nuclei não suporta asset_type={target.asset_type}")

        out_path = Path(tempfile.mkdtemp(prefix="cai-nuclei-")) / "out.jsonl"
        rate_limit = str(options.get("rate_limit", 50))
        severity_filter = options.get("severity", "low,medium,high,critical")

        cmd = [
            self.nuclei_bin,
            "-u",
            target.value,
            "-jsonl",
            "-o",
            str(out_path),
            "-rl",
            rate_limit,
            "-severity",
            severity_filter,
            "-silent",
            "-no-color",
        ]
        if self.templates_dir:
            cmd.extend(["-t", self.templates_dir])
        if templates := options.get("templates"):
            cmd.extend(["-t", templates])

        log.info("nuclei.start_scan", cmd=cmd)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        native_id = str(uuid4())
        self._output_paths[native_id] = out_path

        async def _wait() -> int:
            await proc.communicate()
            return proc.returncode or 0

        self._tasks[native_id] = asyncio.create_task(_wait())
        return ScanHandle(
            adapter=self.name,
            native_id=native_id,
            metadata={"target": target.value, "out_path": str(out_path)},
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None:
            return ScanStatus.FAILED
        if not task.done():
            return ScanStatus.RUNNING
        # nuclei retorna 0 mesmo sem findings; só falha em erro real
        return ScanStatus.DONE if task.result() == 0 else ScanStatus.FAILED

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        path = self._output_paths.get(handle.native_id)
        lines: list[dict[str, Any]] = []
        if path and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return RawResults(adapter=self.name, payload=lines)

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()
        for item in raw.payload:
            info = item.get("info", {})
            sev_raw = (info.get("severity") or "low").lower()
            severity = _NUCLEI_SEVERITY.get(sev_raw, Severity.LOW)
            classification = info.get("classification", {})

            cwe = []
            if cwe_list := classification.get("cwe-id"):
                cwe = list(cwe_list) if isinstance(cwe_list, list) else [str(cwe_list)]

            cve_id = None
            if cve_list := classification.get("cve-id"):
                cve_id = (cve_list[0] if isinstance(cve_list, list) else str(cve_list)).upper()

            matched_at = item.get("matched-at") or item.get("host", "")
            target = Target(
                asset_type=AssetType.URL if "://" in matched_at else AssetType.HOST,
                value=matched_at,
            )

            findings.append(
                Finding(
                    scan_id=placeholder,
                    target=target,
                    source_tool=self.name,
                    source_rule_id=item.get("template-id", ""),
                    vuln_id=cve_id,
                    cwe=cwe,
                    title=info.get("name", "Nuclei finding"),
                    description=info.get("description", "")
                    or f"Template {item.get('template-id')} matched.",
                    severity=severity,
                    confidence=Confidence.FIRM,
                    evidence=[
                        Evidence(
                            description=f"Template {item.get('template-id')} match",
                            request=item.get("request"),
                            response=(item.get("response") or "")[:8000],
                            payload=item.get("matcher-name"),
                            snippet=item.get("extracted-results", [None])[0]
                            if isinstance(item.get("extracted-results"), list)
                            else None,
                        )
                    ],
                    remediation=info.get("remediation"),
                )
            )
        log.info("nuclei.normalize_done", findings=len(findings))
        return findings
