"""Trivy adapter — server mode. Faz scan de imagens, fs e config IaC.

Usa o servidor Trivy via HTTP (compose service `trivy`).
Para scan de imagem, dispara `trivy image --server <url>` no kali-toolbox e parseia JSON.
Pra simplificar Fase 2: invoca o `trivy` binário local com `--server` apontando pro container.
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

_TRIVY_SEVERITY: dict[str, Severity] = {
    "UNKNOWN": Severity.LOW,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


class TrivyAdapter:
    """Roda trivy local apontando pro server compartilhado (cache de DB)."""

    name = "trivy"

    def __init__(
        self,
        trivy_bin: str | None = None,
        server_url: str | None = None,
    ) -> None:
        self.trivy_bin = trivy_bin or shutil.which("trivy") or "trivy"
        self.server_url = server_url
        self._tasks: dict[str, asyncio.Task[int]] = {}
        self._outputs: dict[str, Path] = {}

    async def health(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.trivy_bin,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except (FileNotFoundError, PermissionError):
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        out_path = Path(tempfile.mkdtemp(prefix="cai-trivy-")) / "out.json"

        # Modo: image | fs | config | repo
        mode = options.get("mode")
        if mode is None:
            mode = self._mode_for_target(target.asset_type)

        cmd: list[str] = [self.trivy_bin, mode]
        if self.server_url:
            cmd.extend(["--server", self.server_url])

        cmd.extend(["--format", "json", "--output", str(out_path), "--quiet"])

        if severity := options.get("severity"):
            cmd.extend(["--severity", severity])
        if scanners := options.get("scanners"):  # "vuln", "secret", "misconfig"
            cmd.extend(["--scanners", scanners])

        cmd.append(target.value)
        log.info("trivy.start_scan", cmd=cmd)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        native_id = str(uuid4())
        self._outputs[native_id] = out_path

        async def _wait() -> int:
            await proc.communicate()
            return proc.returncode or 0

        self._tasks[native_id] = asyncio.create_task(_wait())
        return ScanHandle(
            adapter=self.name,
            native_id=native_id,
            metadata={"target": target.value, "mode": mode},
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None:
            return ScanStatus.FAILED
        if not task.done():
            return ScanStatus.RUNNING
        return ScanStatus.DONE if task.result() == 0 else ScanStatus.FAILED

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        path = self._outputs.get(handle.native_id)
        if path is None or not path.exists():
            return RawResults(adapter=self.name, payload={"Results": []})
        return RawResults(
            adapter=self.name,
            payload=json.loads(path.read_text(encoding="utf-8")),
        )

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()

        artifact = raw.payload.get("ArtifactName", "unknown")
        artifact_type = raw.payload.get("ArtifactType", "unknown")
        target = Target(asset_type=AssetType.IMAGE, value=artifact, label=artifact_type)

        for result in raw.payload.get("Results", []):
            target_in_result = result.get("Target", artifact)
            sub_target = Target(asset_type=AssetType.IMAGE, value=target_in_result)

            for v in result.get("Vulnerabilities", []) or []:
                sev = _TRIVY_SEVERITY.get(v.get("Severity", "LOW").upper(), Severity.LOW)
                cwe = v.get("CweIDs") or []
                cvss = v.get("CVSS", {})
                cvss_score = None
                for vendor in ("nvd", "redhat", "ubuntu"):
                    if vendor in cvss and cvss[vendor].get("V3Score"):
                        cvss_score = cvss[vendor]["V3Score"]
                        break

                findings.append(
                    Finding(
                        scan_id=placeholder,
                        target=sub_target,
                        source_tool=self.name,
                        source_rule_id=v.get("VulnerabilityID"),
                        vuln_id=v.get("VulnerabilityID"),
                        cwe=cwe,
                        title=f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title') or v.get('VulnerabilityID')}",
                        description=v.get("Description", "")[:2000],
                        severity=sev,
                        confidence=Confidence.FIRM,
                        evidence=[
                            Evidence(
                                description=f"Pacote vulnerável: {v.get('PkgName')} {v.get('InstalledVersion')} → {v.get('FixedVersion', '(sem fix)')}",
                                snippet=v.get("PrimaryURL"),
                            )
                        ],
                        remediation=(
                            f"Atualizar {v.get('PkgName')} para {v.get('FixedVersion')}"
                            if v.get("FixedVersion")
                            else None
                        ),
                    )
                )

            # Misconfigurations (IaC, Dockerfile)
            for m in result.get("Misconfigurations", []) or []:
                sev = _TRIVY_SEVERITY.get(m.get("Severity", "LOW").upper(), Severity.LOW)
                findings.append(
                    Finding(
                        scan_id=placeholder,
                        target=sub_target,
                        source_tool=self.name,
                        source_rule_id=m.get("ID"),
                        title=m.get("Title", "Trivy misconfiguration"),
                        description=m.get("Description", ""),
                        severity=sev,
                        confidence=Confidence.FIRM,
                        evidence=[
                            Evidence(
                                description=m.get("Message", "(sem detalhe)"),
                                snippet=m.get("Resolution"),
                            )
                        ],
                        remediation=m.get("Resolution"),
                    )
                )

            # Secrets (no fs/repo scan)
            for s in result.get("Secrets", []) or []:
                sev = _TRIVY_SEVERITY.get(s.get("Severity", "HIGH").upper(), Severity.HIGH)
                findings.append(
                    Finding(
                        scan_id=placeholder,
                        target=sub_target,
                        source_tool=self.name,
                        source_rule_id=s.get("RuleID"),
                        title=f"Secret exposto: {s.get('Title')}",
                        description=f"Linha {s.get('StartLine')}: {s.get('Match', '')[:300]}",
                        severity=sev,
                        confidence=Confidence.FIRM,
                        evidence=[
                            Evidence(
                                description=f"{s.get('Category')}: {s.get('Title')}",
                                snippet=s.get("Match"),
                            )
                        ],
                    )
                )

        log.info("trivy.normalize_done", findings=len(findings), target=artifact)
        return findings

    @staticmethod
    def _mode_for_target(asset_type: AssetType) -> str:
        if asset_type == AssetType.IMAGE:
            return "image"
        if asset_type == AssetType.REPO:
            return "repo"
        return "fs"
