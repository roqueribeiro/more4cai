"""Nmap adapter — runs nmap as subprocess, parses XML output."""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Any

import structlog
from libnmap.parser import NmapParser, NmapParserException

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


class NmapAdapter:
    """Roda nmap como subprocess. Cada scan tem seu próprio handle (PID + XML path)."""

    name = "nmap"

    DEFAULT_ARGS = ["-sV", "-T4", "--top-ports", "1000", "-Pn"]

    def __init__(self, nmap_bin: str | None = None) -> None:
        self.nmap_bin = nmap_bin or shutil.which("nmap") or "nmap"
        self._tasks: dict[str, asyncio.Task[tuple[int, str]]] = {}
        self._xml_paths: dict[str, Path] = {}

    async def health(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nmap_bin,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except (FileNotFoundError, PermissionError):
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        if target.asset_type not in (AssetType.HOST, AssetType.URL, AssetType.DOMAIN):
            raise ValueError(f"nmap não suporta asset_type={target.asset_type}")

        host = self._extract_host(target.value)
        extra_args: list[str] = options.get("nmap_args", self.DEFAULT_ARGS)

        xml_path = Path(tempfile.mkdtemp(prefix="cai-nmap-")) / "scan.xml"
        cmd = [self.nmap_bin, *extra_args, "-oX", str(xml_path), host]
        log.info("nmap.start_scan", cmd=cmd)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        native_id = str(proc.pid)
        self._xml_paths[native_id] = xml_path
        self._tasks[native_id] = asyncio.create_task(self._await_proc(proc))

        return ScanHandle(
            adapter=self.name,
            native_id=native_id,
            metadata={"target": target.value, "xml_path": str(xml_path), "cmd": cmd},
        )

    async def _await_proc(self, proc: asyncio.subprocess.Process) -> tuple[int, str]:
        _, stderr = await proc.communicate()
        return (proc.returncode or 0), stderr.decode(errors="replace")

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None:
            return ScanStatus.FAILED
        if not task.done():
            return ScanStatus.RUNNING
        rc, _ = task.result()
        return ScanStatus.DONE if rc == 0 else ScanStatus.FAILED

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        xml_path = self._xml_paths.get(handle.native_id)
        if xml_path is None or not xml_path.exists():
            raise FileNotFoundError(f"XML não encontrado: {xml_path}")
        xml = xml_path.read_text(encoding="utf-8")
        return RawResults(adapter=self.name, payload=xml)

    async def cleanup(self, handle: ScanHandle) -> None:
        """Cancela task pendente, drena excecao, remove temp dir."""
        from orchestrator.adapters._cleanup import cleanup_subprocess_handle

        await cleanup_subprocess_handle(
            native_id=handle.native_id,
            tasks=self._tasks,  # type: ignore[arg-type]
            output_paths=self._xml_paths,
            adapter_name=self.name,
        )

    async def normalize(self, raw: RawResults) -> list[Finding]:
        from uuid import uuid4

        findings: list[Finding] = []
        try:
            report = NmapParser.parse(raw.payload)
        except NmapParserException as e:
            log.error("nmap.parse_failed", error=str(e))
            return findings

        # scan_id é injetado fora — aqui usamos placeholder; o pipeline reescreve.
        placeholder_scan_id = uuid4()

        for host in report.hosts:
            host_addr = host.address
            host_target = Target(
                asset_type=AssetType.HOST,
                value=host_addr,
                label=host.hostnames[0] if host.hostnames else None,
            )

            for service in host.services:
                if service.state != "open":
                    continue

                banner = service.banner or service.service or "unknown"
                title = f"Open port {service.port}/{service.protocol} ({service.service})"
                description = (
                    f"Porta {service.port}/{service.protocol} aberta no host {host_addr}. "
                    f"Serviço detectado: {banner}."
                )

                # nmap descobre, não classifica como vulnerabilidade per se.
                # Severity baixa por padrão; o AIAnalyzer pode ajustar com base em serviço (ex.: telnet exposto = high).
                severity = self._severity_for_service(service.service, service.port)

                findings.append(
                    Finding(
                        scan_id=placeholder_scan_id,
                        target=Target(
                            asset_type=AssetType.PORT,
                            value=f"{host_addr}:{service.port}/{service.protocol}",
                            label=service.service,
                        ),
                        source_tool=self.name,
                        source_rule_id=f"port-{service.port}-{service.protocol}",
                        title=title,
                        description=description,
                        severity=severity,
                        confidence=Confidence.CERTAIN,
                        evidence=[Evidence(description=f"Banner: {banner}", snippet=banner)],
                    )
                )

        log.info("nmap.normalize_done", findings=len(findings), host_count=len(report.hosts))
        return findings

    @staticmethod
    def _extract_host(value: str) -> str:
        # aceita URL ou host; nmap quer só host/IP/CIDR
        if "://" in value:
            from urllib.parse import urlparse

            return urlparse(value).hostname or value
        return value.split("/")[0]  # remove path se vier "host:port/path"

    @staticmethod
    def _severity_for_service(service: str | None, port: int) -> Severity:
        """Heurística simples; AIAnalyzer refina com contexto."""
        if service is None:
            return Severity.LOW
        s = service.lower()
        # serviços de risco alto se expostos sem motivo
        if s in {"telnet", "ftp", "rsh", "rexec", "rlogin", "tftp"}:
            return Severity.HIGH
        if s in {
            "smb",
            "netbios-ssn",
            "microsoft-ds",
            "ms-sql-s",
            "mysql",
            "postgresql",
            "mongodb",
            "redis",
        }:
            return Severity.MEDIUM
        if port in {22, 80, 443, 8080, 8443}:
            return Severity.INFO
        return Severity.LOW
