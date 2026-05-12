"""Trufflehog adapter — secret detection com verificação ativa de credenciais.

`--only-verified` reduz drasticamente falso positivo (trufflehog tenta usar a credencial).
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


class TrufflehogAdapter:
    name = "trufflehog"

    def __init__(self, bin_path: str | None = None) -> None:
        self.bin = bin_path or shutil.which("trufflehog") or "trufflehog"
        self._tasks: dict[str, asyncio.Task[int]] = {}
        self._outs: dict[str, Path] = {}

    async def health(self) -> bool:
        try:
            p = await asyncio.create_subprocess_exec(
                self.bin, "--version",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await p.communicate()
            return p.returncode == 0
        except (FileNotFoundError, PermissionError):
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        if target.asset_type != AssetType.REPO:
            raise ValueError(f"trufflehog espera REPO, recebi {target.asset_type}")

        out_path = Path(tempfile.mkdtemp(prefix="cai-trufflehog-")) / "out.jsonl"
        only_verified = options.get("only_verified", True)

        cmd = [self.bin, "git", target.value, "--json"]
        if only_verified:
            cmd.append("--only-verified")
        if since := options.get("since_commit"):
            cmd.extend(["--since-commit", since])

        log.info("trufflehog.start_scan", cmd=cmd)

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
            metadata={"repo": target.value, "out": str(out_path)},
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None:
            return ScanStatus.FAILED
        if not task.done():
            return ScanStatus.RUNNING
        return ScanStatus.DONE if task.result() == 0 else ScanStatus.FAILED

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        path = self._outs.get(handle.native_id)
        items: list[dict[str, Any]] = []
        if path and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
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
            verified = bool(item.get("Verified", False))
            detector = item.get("DetectorName") or item.get("DetectorType", "Unknown")

            source_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
            file_path = source_meta.get("file", "")
            line = source_meta.get("line", "?")

            target = Target(
                asset_type=AssetType.REPO,
                value=f"{file_path}:{line}" if file_path else "(unknown location)",
            )

            findings.append(
                Finding(
                    scan_id=placeholder,
                    target=target,
                    source_tool=self.name,
                    source_rule_id=detector,
                    title=(
                        f"Secret VERIFICADO ({detector})"
                        if verified
                        else f"Secret detectado ({detector})"
                    ),
                    description=(
                        f"Trufflehog encontrou {detector} em {file_path}:{line}. "
                        + ("CREDENCIAL ATIVA — incidente." if verified else "Não verificado.")
                    ),
                    severity=Severity.CRITICAL if verified else Severity.MEDIUM,
                    confidence=Confidence.CERTAIN if verified else Confidence.TENTATIVE,
                    evidence=[
                        Evidence(
                            description=f"{detector} {'(verified)' if verified else ''}",
                            snippet=(item.get("Raw") or "")[:300],
                        )
                    ],
                )
            )
        log.info("trufflehog.normalize_done", findings=len(findings))
        return findings
