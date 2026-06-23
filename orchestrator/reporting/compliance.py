"""Compliance mapping — traduz cada `Finding` em frameworks que auditores e
times de segurança (banco, PCI-QSA, DPO LGPD) consomem direto.

Tudo aqui é **puro e determinístico** (sem I/O, sem rede) → testável e estável.
A cadeia de mapeamento é:

    Finding.cwe  ─┬─►  OWASP Top 10 2021  ─►  PCI DSS 4.0 requisitos
                  └─►  CWE Top 25 (2023)       LGPD artigos
    Finding.cvss_v3 (ou severity→banda)  ─►  CVSS base + rating

O OWASP da triagem de IA (`AITriage.owasp_top10`) vence a derivação por CWE
quando presente (a IA viu o contexto). Sem CWE nem OWASP, a finding entra como
"não classificada" mas ainda conta no risco agregado pela severidade.

Referências:
- OWASP Top 10 2021 CWE mapping (owasp.org/Top10).
- PCI DSS v4.0 (Req. 6.2.4 cobre os ataques comuns de aplicação; demais
  requisitos mapeados por categoria de falha).
- LGPD Lei 13.709/2018 (Art. 46 medidas de segurança; Art. 47 integridade/
  confidencialidade; Art. 48 comunicação de incidente).
- CWE Top 25 Most Dangerous Software Weaknesses (2023).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from orchestrator.domain.schemas import Finding, Severity

# --------------------------------------------------------------------------- #
# CWE → OWASP Top 10 2021                                                       #
# Subconjunto curado dos CWEs que os scanners do stack (nuclei/zap/trivy/      #
# greenbone/nmap) realmente emitem. Não é a lista completa de 200+ — cobre o   #
# que aparece na prática + os CWEs Top 25.                                      #
# --------------------------------------------------------------------------- #
_OWASP_2021: dict[str, tuple[str, ...]] = {
    "A01:2021-Broken Access Control": (
        "CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219",
        "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352",
        "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497",
        "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601",
        "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863",
        "CWE-913", "CWE-922", "CWE-1275",
    ),
    "A02:2021-Cryptographic Failures": (
        "CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322",
        "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328",
        "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337",
        "CWE-338", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757",
        "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-916",
    ),
    "A03:2021-Injection": (
        "CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80",
        "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93",
        "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100",
        "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471",
        "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-652", "CWE-917",
    ),
    "A04:2021-Insecure Design": (
        "CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256",
        "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312",
        "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444",
        "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539",
        "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650",
        "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840",
        "CWE-841", "CWE-927", "CWE-1021", "CWE-1173",
    ),
    "A05:2021-Security Misconfiguration": (
        "CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315",
        "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611",
        "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032",
        "CWE-1174",
    ),
    "A06:2021-Vulnerable and Outdated Components": (
        "CWE-937", "CWE-1035", "CWE-1104",
    ),
    "A07:2021-Identification and Authentication Failures": (
        "CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294",
        "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306",
        "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620",
        "CWE-640", "CWE-798", "CWE-940", "CWE-1216",
    ),
    "A08:2021-Software and Data Integrity Failures": (
        "CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565",
        "CWE-784", "CWE-829", "CWE-830", "CWE-915",
    ),
    "A09:2021-Security Logging and Monitoring Failures": (
        "CWE-117", "CWE-223", "CWE-532", "CWE-778",
    ),
    "A10:2021-Server-Side Request Forgery": (
        "CWE-918",
    ),
}

# inversão CWE → categoria OWASP (primeiro match vence; CWEs são exclusivos no
# mapping oficial então não há ambiguidade real).
_CWE_TO_OWASP: dict[str, str] = {
    cwe: cat for cat, cwes in _OWASP_2021.items() for cwe in cwes
}

# --------------------------------------------------------------------------- #
# OWASP categoria → PCI DSS 4.0 requisitos                                      #
# 6.2.4 = "ataques de software comuns" (cobre todo OWASP em apps bespoke).      #
# Acrescentamos os requisitos específicos por classe de falha.                 #
# --------------------------------------------------------------------------- #
_OWASP_TO_PCI: dict[str, tuple[str, ...]] = {
    "A01:2021-Broken Access Control": ("6.2.4", "7.2.1", "7.2.2"),
    "A02:2021-Cryptographic Failures": ("6.2.4", "4.2.1", "3.5.1"),
    "A03:2021-Injection": ("6.2.4",),
    "A04:2021-Insecure Design": ("6.2.4", "6.2.1"),
    "A05:2021-Security Misconfiguration": ("6.2.4", "2.2.1"),
    "A06:2021-Vulnerable and Outdated Components": ("6.3.1", "6.3.3"),
    "A07:2021-Identification and Authentication Failures": ("6.2.4", "8.3.1"),
    "A08:2021-Software and Data Integrity Failures": ("6.2.4", "6.4.3", "11.6.1"),
    "A09:2021-Security Logging and Monitoring Failures": ("10.2.1", "10.4.1"),
    "A10:2021-Server-Side Request Forgery": ("6.2.4",),
}

# --------------------------------------------------------------------------- #
# OWASP categoria / CWE de exposição de dados → LGPD (Lei 13.709/2018)          #
# --------------------------------------------------------------------------- #
_DATA_EXPOSURE_CWE = {
    "CWE-200", "CWE-201", "CWE-209", "CWE-213", "CWE-312", "CWE-319", "CWE-359",
    "CWE-532", "CWE-538", "CWE-540", "CWE-548", "CWE-552",
}
_OWASP_TO_LGPD: dict[str, tuple[str, ...]] = {
    "A01:2021-Broken Access Control": ("Art. 46", "Art. 47"),
    "A02:2021-Cryptographic Failures": ("Art. 46", "Art. 47"),
    "A09:2021-Security Logging and Monitoring Failures": ("Art. 48",),
}

# CWE Top 25 Most Dangerous Software Weaknesses (2023)
_CWE_TOP25_2023 = {
    "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78", "CWE-20", "CWE-125",
    "CWE-22", "CWE-352", "CWE-434", "CWE-862", "CWE-476", "CWE-287", "CWE-190",
    "CWE-502", "CWE-77", "CWE-119", "CWE-798", "CWE-918", "CWE-306", "CWE-362",
    "CWE-269", "CWE-94", "CWE-863", "CWE-276",
}

# severity → CVSS base "de banda" quando a finding não traz cvss_v3.score.
_SEVERITY_CVSS_BAND: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}
# peso de risco agregado por severidade (índice de exposição).
_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_CWE_RE = re.compile(r"(\d+)")


def normalize_cwe(raw: str) -> str | None:
    """`'89'`, `'CWE-89'`, `'cwe_89'` → `'CWE-89'`. Lixo → None."""
    if not raw:
        return None
    m = _CWE_RE.search(str(raw))
    return f"CWE-{int(m.group(1))}" if m else None  # strip leading zeros → canônico


def _effective_severity(f: Finding) -> Severity:
    if f.ai_triage is not None:
        return f.ai_triage.adjusted_severity
    return f.severity


def cvss_for(f: Finding) -> float:
    """CVSS base da finding: o score real se houver, senão a banda da severity."""
    if f.cvss_v3 is not None and f.cvss_v3.score is not None:
        return round(float(f.cvss_v3.score), 1)
    return _SEVERITY_CVSS_BAND.get(_effective_severity(f), 0.0)


def cvss_rating(score: float) -> str:
    """Rating qualitativo CVSS v3.1."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


@dataclass(frozen=True)
class FindingCompliance:
    """Classificação de compliance de UMA finding."""

    cwe: tuple[str, ...] = ()
    owasp_2021: str | None = None
    pci_dss_4: tuple[str, ...] = ()
    lgpd: tuple[str, ...] = ()
    cwe_top25_2023: tuple[str, ...] = ()
    cvss: float = 0.0
    rating: str = "None"


def classify_finding(f: Finding) -> FindingCompliance:
    """Mapeia uma finding nos frameworks. Determinístico, sem efeitos."""
    cwes = tuple(c for c in (normalize_cwe(x) for x in f.cwe) if c)

    # OWASP: triagem de IA vence; senão deriva do primeiro CWE conhecido.
    owasp: str | None = None
    if f.ai_triage is not None and f.ai_triage.owasp_top10:
        owasp = _canonical_owasp(f.ai_triage.owasp_top10)
    if owasp is None:
        for c in cwes:
            if c in _CWE_TO_OWASP:
                owasp = _CWE_TO_OWASP[c]
                break

    pci = _OWASP_TO_PCI.get(owasp, ()) if owasp else ()

    lgpd: tuple[str, ...] = ()
    if owasp and owasp in _OWASP_TO_LGPD:
        lgpd = _OWASP_TO_LGPD[owasp]
    elif any(c in _DATA_EXPOSURE_CWE for c in cwes):
        lgpd = ("Art. 46", "Art. 47")

    top25 = tuple(c for c in cwes if c in _CWE_TOP25_2023)
    score = cvss_for(f)
    return FindingCompliance(
        cwe=cwes,
        owasp_2021=owasp,
        pci_dss_4=pci,
        lgpd=lgpd,
        cwe_top25_2023=top25,
        cvss=score,
        rating=cvss_rating(score),
    )


def _canonical_owasp(raw: str) -> str | None:
    """Normaliza um rótulo OWASP da IA (`'A03'`, `'A03:2021'`, `'A3'`) na chave
    canônica completa (`'A03:2021-Injection'`)."""
    m = re.search(r"A0?(\d{1,2})", raw)
    if not m:
        return None
    num = int(m.group(1))
    prefix = f"A{num:02d}:2021-"
    for cat in _OWASP_2021:
        if cat.startswith(prefix):
            return cat
    return None


@dataclass(frozen=True)
class ComplianceReport:
    """Visão agregada de compliance de um scan inteiro — o que o relatório
    executivo e o endpoint JSON consomem."""

    total_findings: int = 0
    counts_by_severity: dict[str, int] = field(default_factory=dict)
    counts_by_rating: dict[str, int] = field(default_factory=dict)
    owasp_coverage: dict[str, int] = field(default_factory=dict)
    pci_dss_coverage: dict[str, int] = field(default_factory=dict)
    lgpd_coverage: dict[str, int] = field(default_factory=dict)
    cwe_top25_hits: int = 0
    cwe_top25_unique: tuple[str, ...] = ()
    risk_index: int = 0
    risk_grade: str = "A"
    max_cvss: float = 0.0
    top_risks: tuple[dict, ...] = ()
    per_finding: dict[str, FindingCompliance] = field(default_factory=dict)


def _grade(risk_index: int, has_critical: bool, has_high: bool) -> str:
    """Nota de postura A–F a partir do índice de risco agregado.

    A nota nunca é melhor que C com qualquer crítico aberto, nem que B com alto."""
    if risk_index == 0:
        return "A"
    if has_critical:
        base = "F" if risk_index >= 80 else "E" if risk_index >= 40 else "D"
        return base
    if has_high:
        return "D" if risk_index >= 45 else "C"
    if risk_index >= 20:
        return "C"
    if risk_index >= 5:
        return "B"
    return "B" if risk_index else "A"


def build_compliance_report(
    findings: list[Finding], *, top_n: int = 10
) -> ComplianceReport:
    """Agrega a classificação de todas as findings num relatório de compliance."""
    counts_sev: dict[str, int] = {}
    counts_rating: dict[str, int] = {}
    owasp_cov: dict[str, int] = {}
    pci_cov: dict[str, int] = {}
    lgpd_cov: dict[str, int] = {}
    top25_unique: set[str] = set()
    per_finding: dict[str, FindingCompliance] = {}
    risk_index = 0
    max_cvss = 0.0
    has_critical = has_high = False
    scored: list[tuple[float, Finding, FindingCompliance]] = []

    for f in findings:
        fc = classify_finding(f)
        per_finding[str(f.id)] = fc
        eff = _effective_severity(f)
        counts_sev[eff.value] = counts_sev.get(eff.value, 0) + 1
        counts_rating[fc.rating] = counts_rating.get(fc.rating, 0) + 1
        if fc.owasp_2021:
            owasp_cov[fc.owasp_2021] = owasp_cov.get(fc.owasp_2021, 0) + 1
        for req in fc.pci_dss_4:
            pci_cov[req] = pci_cov.get(req, 0) + 1
        for art in fc.lgpd:
            lgpd_cov[art] = lgpd_cov.get(art, 0) + 1
        top25_unique.update(fc.cwe_top25_2023)
        risk_index += _SEVERITY_WEIGHT.get(eff, 0)
        max_cvss = max(max_cvss, fc.cvss)
        has_critical = has_critical or eff is Severity.CRITICAL
        has_high = has_high or eff is Severity.HIGH
        scored.append((fc.cvss, f, fc))

    risk_index = min(risk_index, 100)
    scored.sort(key=lambda t: t[0], reverse=True)
    top_risks = tuple(
        {
            "id": str(f.id),
            "title": f.title,
            "severity": _effective_severity(f).value,
            "cvss": fc.cvss,
            "rating": fc.rating,
            "owasp": fc.owasp_2021,
            "pci_dss": list(fc.pci_dss_4),
            "cwe": list(fc.cwe),
        }
        for _, f, fc in scored[:top_n]
        if fc.cvss > 0
    )

    return ComplianceReport(
        total_findings=len(findings),
        counts_by_severity=counts_sev,
        counts_by_rating=counts_rating,
        owasp_coverage=dict(sorted(owasp_cov.items())),
        pci_dss_coverage=dict(sorted(pci_cov.items())),
        lgpd_coverage=dict(sorted(lgpd_cov.items())),
        cwe_top25_hits=sum(1 for fc in per_finding.values() if fc.cwe_top25_2023),
        cwe_top25_unique=tuple(sorted(top25_unique)),
        risk_index=risk_index,
        risk_grade=_grade(risk_index, has_critical, has_high),
        max_cvss=max_cvss,
        top_risks=top_risks,
        per_finding=per_finding,
    )


def report_to_dict(r: ComplianceReport) -> dict:
    """Serializa o `ComplianceReport` (frameworks + por-finding) pra JSON —
    consumível por GRC/SIEM (o banco pluga no fluxo de auditoria)."""
    return {
        "summary": {
            "total_findings": r.total_findings,
            "risk_index": r.risk_index,
            "risk_grade": r.risk_grade,
            "max_cvss": r.max_cvss,
            "counts_by_severity": r.counts_by_severity,
            "counts_by_rating": r.counts_by_rating,
            "cwe_top25_hits": r.cwe_top25_hits,
            "cwe_top25_unique": list(r.cwe_top25_unique),
        },
        "frameworks": {
            "owasp_top10_2021": r.owasp_coverage,
            "pci_dss_4_0": r.pci_dss_coverage,
            "lgpd": r.lgpd_coverage,
        },
        "top_risks": list(r.top_risks),
        "per_finding": {
            fid: {
                "cwe": list(fc.cwe),
                "owasp_top10_2021": fc.owasp_2021,
                "pci_dss_4_0": list(fc.pci_dss_4),
                "lgpd": list(fc.lgpd),
                "cwe_top25_2023": list(fc.cwe_top25_2023),
                "cvss": fc.cvss,
                "rating": fc.rating,
            }
            for fid, fc in r.per_finding.items()
        },
    }
