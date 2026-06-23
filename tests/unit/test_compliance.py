"""Compliance mapping engine — determinístico, sem I/O. Cada caso fixa o
contrato CWE→OWASP→PCI/LGPD + CVSS + nota de postura que o relatório executivo
e o endpoint JSON expõem pro banco/auditoria."""

from __future__ import annotations

from uuid import uuid4

from orchestrator.domain.schemas import (
    AITriage,
    Confidence,
    CvssV3,
    Finding,
    Severity,
    Target,
)
from orchestrator.reporting.compliance import (
    build_compliance_report,
    classify_finding,
    cvss_for,
    cvss_rating,
    normalize_cwe,
    report_to_dict,
)

_TARGET = Target(asset_type="url", value="https://app.bank.example", criticality=Severity.HIGH)


def _finding(
    *,
    cwe: list[str] | None = None,
    severity: Severity = Severity.MEDIUM,
    cvss: float | None = None,
    owasp: str | None = None,
    title: str = "Finding",
) -> Finding:
    triage = None
    if owasp is not None:
        triage = AITriage(
            adjusted_severity=severity,
            rationale="ai",
            model_used="test-model",
            owasp_top10=owasp,
        )
    return Finding(
        scan_id=uuid4(),
        target=_TARGET,
        source_tool="nuclei",
        title=title,
        description="desc",
        severity=severity,
        cwe=cwe or [],
        cvss_v3=CvssV3(score=cvss) if cvss is not None else None,
        confidence=Confidence.FIRM,
        ai_triage=triage,
    )


# --- normalize_cwe ----------------------------------------------------------


def test_normalize_cwe_forms():
    assert normalize_cwe("89") == "CWE-89"
    assert normalize_cwe("CWE-89") == "CWE-89"
    assert normalize_cwe("cwe_89") == "CWE-89"
    assert normalize_cwe("CWE-0089") == "CWE-89"
    assert normalize_cwe("garbage") is None
    assert normalize_cwe("") is None


# --- CVSS -------------------------------------------------------------------


def test_cvss_uses_real_score_when_present():
    assert cvss_for(_finding(cvss=8.6, severity=Severity.MEDIUM)) == 8.6


def test_cvss_falls_back_to_severity_band():
    assert cvss_for(_finding(severity=Severity.CRITICAL)) == 9.5
    assert cvss_for(_finding(severity=Severity.HIGH)) == 7.5
    assert cvss_for(_finding(severity=Severity.MEDIUM)) == 5.0
    assert cvss_for(_finding(severity=Severity.LOW)) == 2.5
    assert cvss_for(_finding(severity=Severity.INFO)) == 0.0


def test_cvss_rating_bands():
    assert cvss_rating(9.1) == "Critical"
    assert cvss_rating(7.0) == "High"
    assert cvss_rating(4.0) == "Medium"
    assert cvss_rating(0.1) == "Low"
    assert cvss_rating(0.0) == "None"


# --- classify_finding -------------------------------------------------------


def test_sql_injection_maps_owasp_pci_top25():
    fc = classify_finding(_finding(cwe=["CWE-89"], severity=Severity.CRITICAL))
    assert fc.owasp_2021 == "A03:2021-Injection"
    assert "6.2.4" in fc.pci_dss_4
    assert "CWE-89" in fc.cwe_top25_2023  # SQLi está no CWE Top 25
    assert fc.cvss == 9.5
    assert fc.rating == "Critical"


def test_ssrf_maps_a10_and_top25():
    fc = classify_finding(_finding(cwe=["CWE-918"], severity=Severity.HIGH))
    assert fc.owasp_2021 == "A10:2021-Server-Side Request Forgery"
    assert "CWE-918" in fc.cwe_top25_2023


def test_data_exposure_maps_lgpd():
    fc = classify_finding(_finding(cwe=["CWE-200"], severity=Severity.MEDIUM))
    # CWE-200 está em A01 (que já mapeia LGPD), e é CWE de exposição de dados.
    assert fc.owasp_2021 == "A01:2021-Broken Access Control"
    assert "Art. 46" in fc.lgpd


def test_ai_owasp_overrides_cwe_derivation():
    # a IA viu contexto → A07; o CWE sozinho não mapearia A07.
    fc = classify_finding(_finding(cwe=["CWE-1"], owasp="A07", severity=Severity.HIGH))
    assert fc.owasp_2021 == "A07:2021-Identification and Authentication Failures"
    assert "8.3.1" in fc.pci_dss_4


def test_unknown_cwe_no_owasp():
    fc = classify_finding(_finding(cwe=["CWE-99999"], severity=Severity.LOW))
    assert fc.owasp_2021 is None
    assert fc.pci_dss_4 == ()
    assert fc.cvss == 2.5


# --- build_compliance_report ------------------------------------------------


def test_empty_report_is_grade_a():
    rep = build_compliance_report([])
    assert rep.total_findings == 0
    assert rep.risk_index == 0
    assert rep.risk_grade == "A"
    assert rep.max_cvss == 0.0
    assert rep.top_risks == ()


def test_critical_finding_drags_grade_down():
    rep = build_compliance_report([_finding(cwe=["CWE-89"], severity=Severity.CRITICAL)])
    assert rep.risk_grade in {"D", "E", "F"}  # nunca melhor que D com crítico aberto
    assert rep.max_cvss == 9.5
    assert rep.owasp_coverage["A03:2021-Injection"] == 1
    assert "6.2.4" in rep.pci_dss_coverage
    assert rep.cwe_top25_hits == 1


def test_aggregates_coverage_across_findings():
    rep = build_compliance_report([
        _finding(cwe=["CWE-89"], severity=Severity.HIGH),   # A03
        _finding(cwe=["CWE-79"], severity=Severity.MEDIUM),  # A03 (XSS)
        _finding(cwe=["CWE-918"], severity=Severity.HIGH),   # A10
    ])
    assert rep.owasp_coverage["A03:2021-Injection"] == 2
    assert rep.owasp_coverage["A10:2021-Server-Side Request Forgery"] == 1
    assert rep.total_findings == 3
    # top_risks ordenado por cvss desc, só com cvss>0
    assert rep.top_risks[0]["cvss"] >= rep.top_risks[-1]["cvss"]


def test_low_only_is_good_grade():
    rep = build_compliance_report([_finding(cwe=["CWE-16"], severity=Severity.LOW)])
    assert rep.risk_grade in {"A", "B"}


def test_report_to_dict_shape():
    rep = build_compliance_report([_finding(cwe=["CWE-89"], severity=Severity.HIGH)])
    d = report_to_dict(rep)
    assert d["summary"]["risk_grade"] == rep.risk_grade
    assert "owasp_top10_2021" in d["frameworks"]
    assert "pci_dss_4_0" in d["frameworks"]
    assert "lgpd" in d["frameworks"]
    assert isinstance(d["top_risks"], list)
    assert isinstance(d["per_finding"], dict)
    # cada per_finding carrega a classificação completa
    one = next(iter(d["per_finding"].values()))
    assert "owasp_top10_2021" in one and "cvss" in one and "rating" in one
