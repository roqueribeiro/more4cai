"""Report rendering — HTML técnico (default) e executivo (compliance).

PDF (WeasyPrint) é opcional via `pip install -e .[pdf]`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader, select_autoescape

from orchestrator.domain.schemas import Finding, Severity

if TYPE_CHECKING:
    from orchestrator.jobs.pipelines import ScanResult


_TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _effective_severity(f: Finding) -> str:
    """Severity ajustada pelo AI, se houver; senão a original."""
    if f.ai_triage is not None:
        return f.ai_triage.adjusted_severity.value
    return f.severity.value


def _selectattr_severity(
    findings: list[Finding],
    keep: list[str],
    eff: Callable[[Finding], str],
) -> list[Finding]:
    """Helper Jinja: filtra findings cuja severity efetiva está em `keep`."""
    return [f for f in findings if eff(f) in keep]


_env.filters["selectattr_severity"] = _selectattr_severity


def render_html(result: ScanResult, out_path: Path) -> Path:
    """Relatório técnico HTML (template default)."""

    sorted_findings = sorted(
        result.findings, key=lambda f: _SEVERITY_ORDER.get(Severity(_effective_severity(f)), 99)
    )

    counts = {sev.value: 0 for sev in Severity}
    for f in result.findings:
        counts[_effective_severity(f)] += 1

    template = _env.get_template("report.html.j2")
    html = template.render(
        scan_id=str(result.scan_id),
        target=result.target,
        findings=sorted_findings,
        counts=counts,
        errors=result.errors,
        effective_severity=_effective_severity,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path


def render_executive(
    result: ScanResult,
    out_path: Path,
    *,
    actor: str | None = None,
    technical_report_path: str | None = None,
    executive_summary: str | None = None,
    top_recommendations: Iterable[str] | None = None,
) -> Path:
    """Relatório executivo HTML — sumário pra stakeholders do engagement."""

    from orchestrator.reporting.compliance import build_compliance_report

    counts = {sev.value: 0 for sev in Severity}
    for f in result.findings:
        counts[_effective_severity(f)] += 1

    compliance = build_compliance_report(result.findings)

    template = _env.get_template("executive.html.j2")
    html = template.render(
        scan_id=str(result.scan_id),
        target=result.target,
        findings=result.findings,
        counts=counts,
        compliance=compliance,
        executive_summary=executive_summary,
        top_recommendations=list(top_recommendations or []),
        actor=actor,
        technical_report_path=technical_report_path
        or (str(result.report_path) if result.report_path else "n/a"),
        effective_severity=_effective_severity,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path


def render_pdf(html_path: Path, pdf_path: Path) -> Path:
    """Converte HTML existente em PDF via WeasyPrint (opcional).

    Requer `pip install -e .[pdf]`. Pode falhar no Windows se libs nativas
    (cairo, pango) não estiverem instaladas — recomendamos rodar em Docker.
    """
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]
    except ImportError as e:
        raise RuntimeError(
            "WeasyPrint não instalado. Use `pip install 'cai-orchestrator[pdf]'`."
        ) from e

    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    return pdf_path
