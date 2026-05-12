"""dnstwist adapter — gera permutações de domínio e checa registros suspeitos."""

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


class DnstwistAdapter:
    name = "dnstwist"

    def __init__(self, bin_path: str | None = None) -> None:
        self.bin = bin_path or shutil.which("dnstwist") or "dnstwist"
        self._tasks: dict[str, asyncio.Task[int]] = {}
        self._outs: dict[str, Path] = {}

    async def health(self) -> bool:
        try:
            p = await asyncio.create_subprocess_exec(
                self.bin,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await p.communicate()
            return p.returncode == 0
        except (FileNotFoundError, PermissionError):
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        if target.asset_type not in (AssetType.DOMAIN, AssetType.HOST):
            raise ValueError(f"dnstwist espera DOMAIN, recebi {target.asset_type}")

        out_path = Path(tempfile.mkdtemp(prefix="cai-dnstwist-")) / "out.json"
        cmd = [
            self.bin,
            "--format",
            "json",
            "--registered",  # só retornar permutações registradas
            "--mxcheck",
            "--whois",
            target.value,
        ]
        if options.get("ssdeep", True):
            cmd.append("--ssdeep")

        log.info("dnstwist.start_scan", cmd=cmd)

        async def _run() -> int:
            with out_path.open("wb") as f:
                p = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=f,
                    stderr=asyncio.subprocess.PIPE,
                )
                await p.communicate()
                return p.returncode or 0

        native_id = str(uuid4())
        self._outs[native_id] = out_path
        self._tasks[native_id] = asyncio.create_task(_run())
        return ScanHandle(
            adapter=self.name,
            native_id=native_id,
            metadata={"domain": target.value},
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None:
            return ScanStatus.FAILED
        if not task.done():
            return ScanStatus.RUNNING
        return ScanStatus.DONE if task.result() == 0 else ScanStatus.FAILED

    async def cleanup(self, handle: ScanHandle) -> None:
        from orchestrator.adapters._cleanup import cleanup_subprocess_handle

        await cleanup_subprocess_handle(
            native_id=handle.native_id,
            tasks=self._tasks,  # type: ignore[arg-type]
            output_paths=self._outs,
            adapter_name=self.name,
        )

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        path = self._outs.get(handle.native_id)
        items: list[dict[str, Any]] = []
        if path and path.exists():
            try:
                items = json.loads(path.read_text(encoding="utf-8") or "[]")
            except json.JSONDecodeError:
                items = []
        return RawResults(adapter=self.name, payload=items)

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()

        for item in raw.payload:
            permutation = item.get("domain", "")
            fuzzer = item.get("fuzzer", "")
            dns_a = item.get("dns_a") or []
            dns_mx = item.get("dns_mx") or []
            ssdeep = item.get("ssdeep_score")

            # heurística de severity: se tem MX + DNS + ssdeep alto = high (phishing ativo provável)
            sev = Severity.LOW
            if dns_a and dns_mx:
                sev = Severity.HIGH if (ssdeep and ssdeep >= 50) else Severity.MEDIUM
            elif dns_a:
                sev = Severity.LOW

            target_obj = Target(asset_type=AssetType.DOMAIN, value=permutation)
            findings.append(
                Finding(
                    scan_id=placeholder,
                    target=target_obj,
                    source_tool=self.name,
                    source_rule_id=f"dnstwist-{fuzzer}",
                    title=f"Typosquat detectado: {permutation} ({fuzzer})",
                    description=(
                        f"Domínio {permutation} registrado, similar ao alvo. "
                        f"DNS A: {dns_a}, MX: {dns_mx}, ssdeep_score: {ssdeep}"
                    ),
                    severity=sev,
                    confidence=Confidence.FIRM,
                    evidence=[
                        Evidence(
                            description=f"fuzzer={fuzzer}",
                            snippet=json.dumps(item, ensure_ascii=False)[:500],
                        )
                    ],
                )
            )
        log.info("dnstwist.normalize_done", findings=len(findings))
        return findings
