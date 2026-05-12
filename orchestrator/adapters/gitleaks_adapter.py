"""Gitleaks adapter — clona repo público e roda gitleaks pra detectar secrets."""

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


class GitleaksAdapter:
    """Clona repo (efêmero) e roda gitleaks. Findings → Severity baseada em rule."""

    name = "gitleaks"

    def __init__(self, gitleaks_bin: str | None = None, git_bin: str | None = None) -> None:
        self.gitleaks_bin = gitleaks_bin or shutil.which("gitleaks") or "gitleaks"
        self.git_bin = git_bin or shutil.which("git") or "git"
        self._tasks: dict[str, asyncio.Task[tuple[int, Path]]] = {}
        self._workdirs: dict[str, Path] = {}

    async def health(self) -> bool:
        try:
            p = await asyncio.create_subprocess_exec(
                self.gitleaks_bin,
                "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await p.communicate()
            return p.returncode == 0
        except (FileNotFoundError, PermissionError):
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        if target.asset_type != AssetType.REPO:
            raise ValueError(f"gitleaks só suporta REPO, recebi {target.asset_type}")

        workdir = Path(tempfile.mkdtemp(prefix="cai-gitleaks-"))
        clone_dir = workdir / "repo"
        report_path = workdir / "report.json"
        depth = str(options.get("clone_depth", 200))

        async def _run() -> tuple[int, Path]:
            # 1. clone --depth N
            clone = await asyncio.create_subprocess_exec(
                self.git_bin,
                "clone",
                "--quiet",
                "--depth",
                depth,
                target.value,
                str(clone_dir),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await clone.communicate()
            if clone.returncode != 0:
                log.error("gitleaks.clone_failed", err=stderr.decode(errors="replace"))
                return clone.returncode or 1, report_path

            # 2. gitleaks detect
            scan_args = [
                self.gitleaks_bin,
                "detect",
                "--source",
                str(clone_dir),
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--no-banner",
                "--exit-code",
                "0",  # achar leak não é "erro"
            ]
            scan = await asyncio.create_subprocess_exec(
                *scan_args,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            await scan.communicate()
            return scan.returncode or 0, report_path

        native_id = str(uuid4())
        self._workdirs[native_id] = workdir
        self._tasks[native_id] = asyncio.create_task(_run())
        return ScanHandle(
            adapter=self.name,
            native_id=native_id,
            metadata={"repo": target.value, "report": str(report_path)},
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None:
            return ScanStatus.FAILED
        if not task.done():
            return ScanStatus.RUNNING
        rc, _ = task.result()
        return ScanStatus.DONE if rc == 0 else ScanStatus.FAILED

    async def cleanup(self, handle: ScanHandle) -> None:
        """Cleanup gitleaks: cancela task + rmtree do workdir (contem clone + report)."""
        from orchestrator.adapters._cleanup import cleanup_subprocess_handle

        await cleanup_subprocess_handle(
            native_id=handle.native_id,
            tasks=self._tasks,  # type: ignore[arg-type]
            output_paths=self._workdirs,  # workdir e' dir; helper detecta is_dir()
            adapter_name=self.name,
        )

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        _, report_path = self._tasks[handle.native_id].result()
        items: list[dict[str, Any]] = []
        if report_path.exists():
            try:
                items = json.loads(report_path.read_text(encoding="utf-8")) or []
            except json.JSONDecodeError:
                items = []
        return RawResults(adapter=self.name, payload=items)

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()
        for item in raw.payload:
            target = Target(
                asset_type=AssetType.REPO,
                value=f"{item.get('File', '')}:{item.get('StartLine', '?')}",
            )
            rule = item.get("RuleID", "unknown")
            findings.append(
                Finding(
                    scan_id=placeholder,
                    target=target,
                    source_tool=self.name,
                    source_rule_id=rule,
                    title=f"Secret detectado: {item.get('Description', rule)}",
                    description=(
                        f"Arquivo {item.get('File')} linha {item.get('StartLine')}, "
                        f"commit {item.get('Commit', '')[:12]}, autor {item.get('Author', '')}"
                    ),
                    severity=Severity.HIGH,  # secret em repo público é high de saída
                    confidence=Confidence.TENTATIVE,  # gitleaks tem ruído; AI confirma
                    evidence=[
                        Evidence(
                            description=f"Match na rule {rule}",
                            snippet=(item.get("Match") or "")[:400],
                        )
                    ],
                )
            )
        log.info("gitleaks.normalize_done", findings=len(findings))
        return findings
