"""Tests for heuristic dedup."""

from __future__ import annotations

from uuid import uuid4

from orchestrator.domain.dedup import heuristic_dedup
from orchestrator.domain.schemas import (
    AssetType,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Target,
)


def _mk(value: str, rule: str, severity: Severity) -> Finding:
    return Finding(
        scan_id=uuid4(),
        target=Target(asset_type=AssetType.URL, value=value),
        source_tool="zap",
        source_rule_id=rule,
        title="t",
        description="d",
        severity=severity,
        confidence=Confidence.FIRM,
        evidence=[Evidence(description="e")],
    )


def test_keeps_higher_severity() -> None:
    a = _mk("http://x", "1", Severity.LOW)
    b = _mk("http://x", "1", Severity.HIGH)  # mesmo deduped_key
    out = heuristic_dedup([a, b])
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_distinct_keys_preserved() -> None:
    a = _mk("http://x", "1", Severity.LOW)
    b = _mk("http://x", "2", Severity.LOW)
    out = heuristic_dedup([a, b])
    assert len(out) == 2


def test_empty_list() -> None:
    assert heuristic_dedup([]) == []


def test_identical_findings_dedup_to_one() -> None:
    a = _mk("http://x", "1", Severity.MEDIUM)
    b = _mk("http://x", "1", Severity.MEDIUM)
    c = _mk("http://x", "1", Severity.MEDIUM)
    out = heuristic_dedup([a, b, c])
    assert len(out) == 1
