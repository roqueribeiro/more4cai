"""Findings queue/summary/resolve — paginação compacta + status workflow.

Cobre a lógica SQL que o smoke ao vivo não congela: dedup por `deduped_key`
entre scans (um item por problema), ordenação por severity, paginação
(offset/total/has_more), filtro de status, e a persistência do `resolve`
(que SOBREVIVE re-scans). Usa SQLite in-memory async (StaticPool = 1 conexão
compartilhada) + chama as funções do router direto (params explícitos, sem
passar pelos defaults `Query(...)` do FastAPI).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from orchestrator.api.deps import Principal
from orchestrator.api.routers import findings as fr
from orchestrator.domain.roles import Role
from orchestrator.persistence.models import FindingRow

SERVICE = Principal(id="service", email="service@local", role=Role.ADMIN, is_service=True)
_T0 = datetime(2026, 6, 29, 12, 0, 0, tzinfo=UTC)


@pytest_asyncio.fixture
async def s() -> AsyncSession:
    """SQLite in-memory async (StaticPool = 1 conexão compartilhada), limpa no fim."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


def _finding(
    scan_id, key, sev, title, *, tool="zap", target="https://x", when=None, remediation="fix it"
) -> FindingRow:
    return FindingRow(
        scan_id=scan_id,
        target_id=uuid4(),
        deduped_key=key,
        source_tool=tool,
        title=title,
        severity=sev,
        confidence="firm",
        payload={"target": {"value": target}, "remediation": remediation, "cwe": ["CWE-1"]},
        discovered_at=when or _T0,
    )


async def _queue(s, **kw):
    params = dict(status="open", min_severity=None, source_tool=None, offset=0, limit=25)
    params.update(kw)
    return await fr.findings_queue(session=s, _principal=SERVICE, **params)


async def test_queue_dedupes_by_key_across_scans(s):
    scan_a, scan_b = uuid4(), uuid4()
    s.add(_finding(scan_a, "K1", "high", "old instance", when=_T0))
    s.add(_finding(scan_b, "K1", "high", "new instance", when=_T0 + timedelta(minutes=5)))
    s.add(_finding(scan_a, "K2", "low", "other", when=_T0))
    await s.commit()

    page = await _queue(s, status="all")
    assert page.total == 2  # K1 colapsado + K2
    k1 = next(i for i in page.items if i.deduped_key == "K1")
    assert k1.title == "new instance"  # a instância MAIS RECENTE


async def test_queue_orders_by_severity_critical_first(s):
    sc = uuid4()
    for key, sev in [("a", "low"), ("b", "critical"), ("c", "medium"), ("d", "high")]:
        s.add(_finding(sc, key, sev, key))
    await s.commit()

    page = await _queue(s, status="all")
    assert [i.severity for i in page.items] == ["critical", "high", "medium", "low"]


async def test_queue_pagination_envelope(s):
    sc = uuid4()
    for n in range(5):
        s.add(_finding(sc, f"k{n}", "medium", f"f{n}"))
    await s.commit()

    p0 = await _queue(s, status="all", offset=0, limit=2)
    assert p0.total == 5 and len(p0.items) == 2 and p0.has_more is True
    p2 = await _queue(s, status="all", offset=4, limit=2)
    assert len(p2.items) == 1 and p2.has_more is False


async def test_queue_compact_has_no_gordo_payload(s):
    s.add(_finding(uuid4(), "k", "high", "t", remediation="rotate the secret"))
    await s.commit()
    item = (await _queue(s, status="all")).items[0]
    # campos compactos presentes; nada de `payload`
    assert item.remediation == "rotate the secret"
    assert item.target == "https://x"
    assert not hasattr(item, "payload")


async def test_resolve_persists_filters_and_summary(s):
    sc = uuid4()
    s.add(_finding(sc, "VULN", "high", "XSS", target="https://app"))
    s.add(_finding(sc, "OK", "low", "header"))
    await s.commit()

    # antes: 2 open
    summ = await fr.findings_summary(session=s, _principal=SERVICE)
    assert summ.open == 2 and summ.resolved == 0

    # resolve VULN
    out = await fr.resolve_finding(
        body=fr.ResolveIn(deduped_key="VULN", status=fr.FindingStatus.RESOLVED, note="sanitized"),
        session=s,
        principal=SERVICE,
    )
    assert out.status == "resolved" and out.resolved_at is not None

    summ = await fr.findings_summary(session=s, _principal=SERVICE)
    assert summ.open == 1 and summ.resolved == 1

    # queue status=open NÃO traz a resolvida; status=resolved traz com a nota
    assert all(i.deduped_key != "VULN" for i in (await _queue(s, status="open")).items)
    resolved = (await _queue(s, status="resolved")).items
    assert len(resolved) == 1 and resolved[0].note == "sanitized"


async def test_resolved_status_survives_a_rescan(s):
    first = uuid4()
    s.add(_finding(first, "VULN", "high", "XSS", when=_T0))
    await s.commit()
    await fr.resolve_finding(
        body=fr.ResolveIn(deduped_key="VULN", status=fr.FindingStatus.RESOLVED, note="fixed"),
        session=s,
        principal=SERVICE,
    )

    # re-scan: NOVA instância, MESMO deduped_key, mais recente
    s.add(_finding(uuid4(), "VULN", "high", "XSS again", when=_T0 + timedelta(hours=1)))
    await s.commit()

    # o status RESOLVED persiste (atrelado à key, não à instância)
    summ = await fr.findings_summary(session=s, _principal=SERVICE)
    assert summ.resolved == 1 and summ.open == 0


async def test_resolve_unknown_key_is_404(s):
    with pytest.raises(HTTPException) as ei:
        await fr.resolve_finding(
            body=fr.ResolveIn(deduped_key="ghost"), session=s, principal=SERVICE
        )
    assert ei.value.status_code == 404
