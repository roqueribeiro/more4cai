"""Subdomain takeover — pipeline subfinder | httpx | nuclei -t takeovers/.

Roda os 3 binários em sequência dentro do kali-toolbox (presume disponíveis no PATH).
"""

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


class SubdomainTakeoverAdapter:
    name = "subdomain_takeover"

    def __init__(
        self,
        subfinder_bin: str | None = None,
        httpx_bin: str | None = None,
        nuclei_bin: str | None = None,
    ) -> None:
        self.subfinder = subfinder_bin or shutil.which("subfinder") or "subfinder"
        self.httpx = httpx_bin or shutil.which("httpx") or "httpx"
        self.nuclei = nuclei_bin or shutil.which("nuclei") or "nuclei"
        self._tasks: dict[str, asyncio.Task[Path]] = {}
        self._workdirs: dict[str, Path] = {}

    async def health(self) -> bool:
        for b in (self.subfinder, self.httpx, self.nuclei):
            try:
                p = await asyncio.create_subprocess_exec(
                    b,
                    "-version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await p.communicate()
                if p.returncode != 0:
                    return False
            except (FileNotFoundError, PermissionError):
                return False
        return True

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        if target.asset_type != AssetType.DOMAIN:
            raise ValueError(f"subdomain_takeover espera DOMAIN, recebi {target.asset_type}")

        workdir = Path(tempfile.mkdtemp(prefix="cai-subtake-"))
        subs_path = workdir / "subs.txt"
        live_path = workdir / "live.txt"
        out_path = workdir / "out.jsonl"

        async def _run() -> Path:
            # 1. subfinder
            sf = await asyncio.create_subprocess_exec(
                self.subfinder,
                "-d",
                target.value,
                "-silent",
                "-o",
                str(subs_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            await sf.communicate()

            # 2. httpx (filtra subs vivos)
            if subs_path.exists():
                hx = await asyncio.create_subprocess_exec(
                    self.httpx,
                    "-l",
                    str(subs_path),
                    "-silent",
                    "-o",
                    str(live_path),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                await hx.communicate()

            # 3. nuclei -t takeovers/
            if live_path.exists():
                nu = await asyncio.create_subprocess_exec(
                    self.nuclei,
                    "-l",
                    str(live_path),
                    "-t",
                    "http/takeovers/",
                    "-jsonl",
                    "-o",
                    str(out_path),
                    "-silent",
                    "-no-color",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                await nu.communicate()

            return out_path

        native_id = str(uuid4())
        self._tasks[native_id] = asyncio.create_task(_run())
        self._workdirs[native_id] = workdir
        return ScanHandle(
            adapter=self.name,
            native_id=native_id,
            metadata={"domain": target.value, "workdir": str(workdir)},
        )

    async def cleanup(self, handle: ScanHandle) -> None:
        from orchestrator.adapters._cleanup import cleanup_subprocess_handle

        await cleanup_subprocess_handle(
            native_id=handle.native_id,
            tasks=self._tasks,  # type: ignore[arg-type]
            output_paths=self._workdirs,
            adapter_name=self.name,
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None:
            return ScanStatus.FAILED
        return ScanStatus.DONE if task.done() else ScanStatus.RUNNING

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        out_path = await self._tasks[handle.native_id]
        items: list[dict[str, Any]] = []
        if out_path.exists():
            for line in out_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return RawResults(adapter=self.name, payload=items)

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()
        for item in raw.payload:
            url = item.get("matched-at") or item.get("host", "")
            target = Target(asset_type=AssetType.URL, value=url)
            findings.append(
                Finding(
                    scan_id=placeholder,
                    target=target,
                    source_tool=self.name,
                    source_rule_id=item.get("template-id", "takeover"),
                    title=f"Possível subdomain takeover: {url}",
                    description=(
                        f"Template {item.get('template-id')} indica que {url} "
                        "aponta pra serviço terceiro desativado. "
                        "Atacante pode reclamar o recurso e servir conteúdo malicioso "
                        "como se fosse o subdomínio do banco."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    evidence=[
                        Evidence(
                            description=f"template={item.get('template-id')}",
                            snippet=(item.get("response") or "")[:400],
                        )
                    ],
                )
            )
        log.info("subdomain_takeover.normalize_done", findings=len(findings))
        return findings
