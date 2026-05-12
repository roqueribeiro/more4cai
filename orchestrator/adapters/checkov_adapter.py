"""Checkov adapter — IaC misconfig scan (Terraform, CloudFormation, K8s manifests, ARM).

Subprocess + JSON output.
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


_CHECKOV_SEVERITY: dict[str, Severity] = {
    "INFO": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


class CheckovAdapter:
    name = "checkov"

    def __init__(self, bin_path: str | None = None) -> None:
        self.bin = bin_path or shutil.which("checkov") or "checkov"
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
        # target.value é o caminho do diretório/arquivo IaC
        out_path = Path(tempfile.mkdtemp(prefix="cai-checkov-")) / "out.json"
        framework = options.get("framework")  # ex: "terraform" "kubernetes" "dockerfile"

        cmd = [
            self.bin,
            "-d",
            target.value,
            "-o",
            "json",
            "--quiet",
            "--soft-fail",
        ]
        if framework:
            cmd.extend(["--framework", framework])

        log.info("checkov.start_scan", cmd=cmd)

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
        return ScanHandle(adapter=self.name, native_id=native_id, metadata={"path": target.value})

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None:
            return ScanStatus.FAILED
        return ScanStatus.DONE if task.done() else ScanStatus.RUNNING

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
        data: Any = {}
        if path and path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8") or "{}")
            except json.JSONDecodeError:
                data = {}
        return RawResults(adapter=self.name, payload=data)

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()

        # checkov pode retornar dict (single framework) ou list (multi). Normalizar.
        payload = raw.payload
        runs = payload if isinstance(payload, list) else [payload]

        for run in runs:
            results = run.get("results") or {}
            failed = results.get("failed_checks") or []
            for check in failed:
                sev_str = (check.get("severity") or "MEDIUM").upper()
                severity = _CHECKOV_SEVERITY.get(sev_str, Severity.MEDIUM)
                file_path = check.get("file_path", "")
                start_line = check.get("file_line_range", [None])[0]

                target = Target(
                    asset_type=AssetType.REPO,
                    value=f"{file_path}:{start_line}" if start_line else file_path,
                )

                findings.append(
                    Finding(
                        scan_id=placeholder,
                        target=target,
                        source_tool=self.name,
                        source_rule_id=check.get("check_id"),
                        title=f"{check.get('check_id')}: {check.get('check_name')}",
                        description=check.get("description", "")[:2000],
                        severity=severity,
                        confidence=Confidence.FIRM,
                        evidence=[
                            Evidence(
                                description=f"resource={check.get('resource')}",
                                snippet=(check.get("code_block") or "")[:400]
                                if isinstance(check.get("code_block"), str)
                                else None,
                            )
                        ],
                        remediation=check.get("guideline"),
                    )
                )

        log.info("checkov.normalize_done", findings=len(findings))
        return findings
