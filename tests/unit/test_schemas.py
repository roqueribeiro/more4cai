"""Tests for Finding schema — dedup key estabilidade, severity ordering."""

from __future__ import annotations

from uuid import uuid4

import pytest

from orchestrator.domain.schemas import (
    AssetType,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Target,
)


def _mk_finding(target_value: str, rule_id: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        scan_id=uuid4(),
        target=Target(asset_type=AssetType.URL, value=target_value),
        source_tool="zap",
        source_rule_id=rule_id,
        title=f"Test finding {rule_id}",
        description="…",
        severity=severity,
        confidence=Confidence.FIRM,
        evidence=[Evidence(description="evidence")],
    )


def test_deduped_key_stable() -> None:
    f1 = _mk_finding("http://x", "10001")
    f2 = _mk_finding("http://x", "10001")
    assert f1.deduped_key == f2.deduped_key


def test_deduped_key_differs_for_different_targets() -> None:
    f1 = _mk_finding("http://x", "10001")
    f2 = _mk_finding("http://y", "10001")
    assert f1.deduped_key != f2.deduped_key


def test_deduped_key_differs_for_different_rules() -> None:
    f1 = _mk_finding("http://x", "10001")
    f2 = _mk_finding("http://x", "10002")
    assert f1.deduped_key != f2.deduped_key


def test_severity_enum_string_values() -> None:
    assert Severity.CRITICAL.value == "critical"
    assert Severity.INFO.value == "info"


def test_finding_extra_forbidden() -> None:
    with pytest.raises(Exception):
        Finding(
            scan_id=uuid4(),
            target=Target(asset_type=AssetType.URL, value="http://x"),
            source_tool="zap",
            title="t",
            description="d",
            severity=Severity.LOW,
            extra_field="not allowed",  # type: ignore[call-arg]
        )


def test_finding_evidence_optional() -> None:
    f = _mk_finding("http://x", "10001")
    assert isinstance(f.evidence, list)
    f2 = Finding(
        scan_id=uuid4(),
        target=Target(asset_type=AssetType.HOST, value="1.2.3.4"),
        source_tool="nmap",
        title="open 22",
        description="ssh open",
        severity=Severity.INFO,
    )
    assert f2.evidence == []


def test_target_frozen() -> None:
    t = Target(asset_type=AssetType.URL, value="http://x")
    with pytest.raises(Exception):
        t.value = "other"  # type: ignore[misc]
