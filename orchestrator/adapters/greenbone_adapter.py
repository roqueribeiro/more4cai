"""Greenbone Vulnerability Manager (OpenVAS) adapter — via python-gvm sobre TLS/socket.

Vida típica: cria task com config 'Full and fast', dispara, aguarda, baixa report XML.
Pré-requisitos:
  - Stack Greenbone Community Edition rodando (compose oficial deles)
  - Feed sync inicial concluído
  - GMP socket exposto OU GMP/TLS exposto
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import structlog
from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

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


_OPENVAS_THREAT: dict[str, Severity] = {
    "Log": Severity.INFO,
    "Debug": Severity.INFO,
    "Low": Severity.LOW,
    "Medium": Severity.MEDIUM,
    "High": Severity.HIGH,
}


# UUID built-in do scan config "Full and fast"
_FULL_AND_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
# UUID built-in do scanner OpenVAS Default
_OPENVAS_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"


class GreenboneAdapter:
    name = "greenbone"

    def __init__(
        self,
        username: str = "admin",
        password: str = "",
        host: str | None = None,
        port: int = 9390,
        socket_path: str | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.socket_path = socket_path
        self._scans: dict[str, dict[str, Any]] = {}

    def _connect(self) -> Any:
        if self.socket_path:
            return UnixSocketConnection(path=self.socket_path)
        if self.host:
            return TLSConnection(hostname=self.host, port=self.port)
        raise RuntimeError("Greenbone: configure host (TLS) ou socket_path")

    def _gmp_session(self) -> Any:
        return Gmp(connection=self._connect(), transform=EtreeTransform())

    async def health(self) -> bool:
        def _check() -> bool:
            try:
                with self._gmp_session() as g:
                    g.authenticate(self.username, self.password)
                return True
            except Exception as e:  # noqa: BLE001
                log.warning("greenbone.health_failed", error=str(e))
                return False

        return await asyncio.to_thread(_check)

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        if target.asset_type not in (AssetType.HOST, AssetType.DOMAIN):
            raise ValueError(f"greenbone espera HOST/DOMAIN, recebi {target.asset_type}")

        config_id = options.get("config_id", _FULL_AND_FAST_CONFIG)
        scanner_id = options.get("scanner_id", _OPENVAS_SCANNER)
        port_list_id = options.get("port_list_id")

        def _run() -> dict[str, str]:
            with self._gmp_session() as g:
                g.authenticate(self.username, self.password)

                # 1. cria target
                tgt_resp = g.create_target(
                    name=f"cai-{target.value}-{uuid4().hex[:8]}",
                    hosts=[target.value],
                    port_list_id=port_list_id,
                )
                tgt_id = tgt_resp.get("id")

                # 2. cria task
                task_resp = g.create_task(
                    name=f"cai-task-{uuid4().hex[:8]}",
                    config_id=config_id,
                    target_id=tgt_id,
                    scanner_id=scanner_id,
                )
                task_id = task_resp.get("id")

                # 3. start
                start_resp = g.start_task(task_id=task_id)
                report_id = start_resp.findtext("report_id") or ""

                return {"task_id": task_id, "target_id": tgt_id, "report_id": report_id}

        info = await asyncio.to_thread(_run)
        native_id = str(uuid4())
        self._scans[native_id] = info
        return ScanHandle(
            adapter=self.name,
            native_id=native_id,
            metadata=info | {"target": target.value},
        )

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        info = self._scans.get(handle.native_id)
        if info is None:
            return ScanStatus.FAILED

        def _check() -> str:
            with self._gmp_session() as g:
                g.authenticate(self.username, self.password)
                resp = g.get_task(task_id=info["task_id"])
                return (resp.findtext(".//task/status") or "").strip()

        status = await asyncio.to_thread(_check)
        if status in ("Done", "Stopped"):
            return ScanStatus.DONE
        if status in ("Interrupted", "Stop Requested"):
            return ScanStatus.FAILED
        return ScanStatus.RUNNING

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        info = self._scans[handle.native_id]

        def _fetch() -> str:
            with self._gmp_session() as g:
                g.authenticate(self.username, self.password)
                # XML report (tipo "PDF" não — usar "XML" report format)
                # Default report format XML UUID:
                xml_format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"
                resp = g.get_report(
                    report_id=info["report_id"],
                    report_format_id=xml_format_id,
                    ignore_pagination=True,
                    details=True,
                )
                from defusedxml import ElementTree as ET

                return ET.tostring(resp, encoding="unicode")

        xml = await asyncio.to_thread(_fetch)
        return RawResults(adapter=self.name, payload=xml)

    async def normalize(self, raw: RawResults) -> list[Finding]:
        # defusedxml previne XXE / billion-laughs em XML externo (Greenbone GMP).
        # Mantemos a API ElementTree-compatible; defusedxml.fromstring rejeita
        # DTD/entities por default.
        from defusedxml import ElementTree as ET
        from defusedxml.common import EntitiesForbidden, NotSupportedError

        findings: list[Finding] = []
        placeholder = uuid4()
        try:
            root = ET.fromstring(raw.payload)
        except (ET.ParseError, EntitiesForbidden, NotSupportedError) as e:
            log.error("greenbone.parse_failed", error=str(e))
            return findings

        for result in root.iter("result"):
            host = result.findtext("host", default="")
            port = result.findtext("port", default="")
            nvt = result.find("nvt")
            oid = nvt.get("oid") if nvt is not None else ""
            name = result.findtext("name", default="")
            threat = result.findtext("threat", default="Low")
            severity = _OPENVAS_THREAT.get(threat, Severity.LOW)
            cvss_score = result.findtext("severity")
            cve = ""
            if nvt is not None:
                refs = nvt.find("refs")
                if refs is not None:
                    for ref in refs.findall("ref"):
                        if ref.get("type") == "cve":
                            cve = ref.get("id", "")
                            break

            target_obj = Target(
                asset_type=AssetType.PORT if port else AssetType.HOST,
                value=f"{host}:{port}" if port else host,
            )

            findings.append(
                Finding(
                    scan_id=placeholder,
                    target=target_obj,
                    source_tool=self.name,
                    source_rule_id=oid,
                    vuln_id=cve or None,
                    title=name or f"Greenbone {oid}",
                    description=(result.findtext("description") or "")[:2000],
                    severity=severity,
                    confidence=Confidence.FIRM,
                    evidence=[
                        Evidence(
                            description=f"NVT OID {oid}",
                            snippet=(result.findtext("description") or "")[:400],
                        )
                    ],
                )
            )

        log.info("greenbone.normalize_done", findings=len(findings))
        return findings
