"""kube-bench adapter — CIS Kubernetes Benchmark.

Subprocess + JSON output. Roda contra cluster atual (kubeconfig montado).
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


class KubeBenchAdapter:
    name = "kube_bench"

    def __init__(self, bin_path: str | None = None) -> None:
        self.bin = bin_path or shutil.which("kube-bench") or "kube-bench"
        self._tasks: dict[str, asyncio.Task[int]] = {}
        self._outs: dict[str, Path] = {}

    async def health(self) -> bool:
        try:
            p = await asyncio.create_subprocess_exec(
                self.bin,
                "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await p.communicate()
            return p.returncode == 0
        except (FileNotFoundError, PermissionError):
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        out_path = Path(tempfile.mkdtemp(prefix="cai-kbench-")) / "out.json"
        targets_arg = options.get("targets", "master,node,etcd,policies")

        cmd = [
            self.bin,
            "run",
            "--targets",
            targets_arg,
            "--json",
        ]

        log.info("kube_bench.start_scan", cmd=cmd)

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
            metadata={"cluster": target.value, "targets": targets_arg},
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None:
            return ScanStatus.FAILED
        return ScanStatus.DONE if task.done() else ScanStatus.RUNNING

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        path = self._outs.get(handle.native_id)
        data: dict[str, Any] = {}
        if path and path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8") or "{}")
            except json.JSONDecodeError:
                data = {}
        return RawResults(adapter=self.name, payload=data)

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()

        # kube-bench: { "Controls": [ { "tests": [ { "results": [ ... ] } ] } ] }
        for ctrl in raw.payload.get("Controls", []):
            for test in ctrl.get("tests", []):
                for r in test.get("results", []):
                    status = (r.get("status") or "").upper()
                    if status != "FAIL":
                        continue
                    sev_str = (r.get("scored", True), r.get("test_number", ""))
                    # kube-bench não tem severity nativo; mapear: scored fail = MEDIUM
                    severity = Severity.MEDIUM if r.get("scored", True) else Severity.LOW
                    target = Target(
                        asset_type=AssetType.K8S_RESOURCE,
                        value=r.get("test_number", "?"),
                    )
                    findings.append(
                        Finding(
                            scan_id=placeholder,
                            target=target,
                            source_tool=self.name,
                            source_rule_id=r.get("test_number", "?"),
                            title=f"CIS {r.get('test_number')}: {r.get('test_desc', '')}",
                            description=r.get("audit", "") or "",
                            severity=severity,
                            confidence=Confidence.FIRM,
                            evidence=[
                                Evidence(
                                    description=f"actual: {r.get('actual_value', '')[:300]}",
                                    snippet=r.get("expected_result"),
                                )
                            ],
                            remediation=r.get("remediation"),
                        )
                    )
        log.info("kube_bench.normalize_done", findings=len(findings))
        return findings
