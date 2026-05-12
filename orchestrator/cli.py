"""CLI: `cai scan` e `cai exposure` para uso direto sem REST."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Annotated

import structlog
import typer
from rich.console import Console
from rich.table import Table

from orchestrator.config import settings
from orchestrator.domain.schemas import AssetType, Severity, Target
from orchestrator.jobs.exposure import run_exposure_scan
from orchestrator.jobs.pipelines import run_scan

app = typer.Typer(
    name="cai",
    help="CAI orchestrator — vulnerability analysis platform",
    no_args_is_help=True,
)

console = Console()


def _setup_logging() -> None:
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            (
                structlog.processors.JSONRenderer()
                if settings.LOG_FORMAT == "json"
                else structlog.dev.ConsoleRenderer()
            ),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
    )


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="URL ou host alvo")],
    asset_type: Annotated[str, typer.Option(help="host|url|domain")] = "url",
    criticality: Annotated[str, typer.Option(help="info|low|medium|high|critical")] = "medium",
    contains_pii: Annotated[bool, typer.Option(help="alvo trata dados pessoais (rota AI local)")] = False,
    skip_ai: Annotated[bool, typer.Option(help="pula triagem AI")] = False,
    active_zap: Annotated[bool, typer.Option(help="ZAP active scan (mais agressivo)")] = False,
) -> None:
    """Roda Nmap + ZAP contra o alvo, triagem AI e gera relatorio HTML."""
    _setup_logging()

    t = Target(
        asset_type=AssetType(asset_type),
        value=target,
        criticality=Severity(criticality),
        contains_pii=contains_pii,
    )

    console.print(f"[bold cyan]CAI[/] starting scan against [bold]{t.value}[/]")
    console.print(
        f"  asset_type={t.asset_type} criticality={t.criticality} pii={t.contains_pii}"
    )
    console.print()

    options = {"zap": {"active": active_zap}}
    result = asyncio.run(run_scan(t, skip_ai=skip_ai, options=options))

    table = Table(title="Findings — resumo")
    table.add_column("Tool")
    table.add_column("Severity")
    table.add_column("Title")
    for f in sorted(result.findings, key=lambda x: x.severity)[:20]:
        sev = f.ai_triage.adjusted_severity if f.ai_triage else f.severity
        table.add_row(f.source_tool, sev, f.title[:80])
    console.print(table)

    if result.errors:
        console.print(f"[yellow]Avisos:[/] {result.errors}")

    if result.report_path:
        console.print(f"\n[green]Relatorio:[/] {result.report_path.resolve()}")


@app.command()
def exposure(
    company_name: Annotated[str, typer.Argument(help="Nome da empresa/banco")],
    domains: Annotated[list[str], typer.Option(help="Domínios do banco (repetir flag)")] = [],
    github_orgs: Annotated[list[str], typer.Option(help="Orgs GitHub (repetir flag)")] = [],
    dorks: Annotated[list[str], typer.Option(help="Dorks GitHub (repetir flag)")] = [],
    config_file: Annotated[
        Path | None,
        typer.Option(help="YAML de config (sobrescreve flags)"),
    ] = None,
    skip_ai: Annotated[bool, typer.Option(help="pula triagem AI")] = False,
) -> None:
    """Scan OSINT/Exposure externa (Fase 2.5). Read-only, sem autorizacao requerida."""
    _setup_logging()

    if config_file and config_file.exists():
        import yaml

        cfg = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        company = cfg.get("company", {})
        company_name = company.get("name", company_name)
        domains = company.get("domains", domains)
        github_orgs = company.get("github_orgs", github_orgs)
        # gerar dorks a partir do template + internal_strings
        if "dorks_template" in cfg:
            tpl = cfg["dorks_template"]
            internals = company.get("internal_strings", [])
            for t in tpl:
                for d in domains:
                    dorks.append(t.format(domain=d, internal_string="", github_org=""))
                for s in internals:
                    dorks.append(t.format(domain="", internal_string=s, github_org=""))
                for g in github_orgs:
                    dorks.append(t.format(domain="", internal_string="", github_org=g))
            dorks = list({d.strip() for d in dorks if d.strip()})

    console.print(f"[bold cyan]CAI exposure[/] for [bold]{company_name}[/]")
    console.print(f"  domains={domains}")
    console.print(f"  github_orgs={github_orgs}")
    console.print(f"  dorks={len(dorks)}")
    console.print()

    result = asyncio.run(
        run_exposure_scan(
            company_name=company_name,
            domains=domains,
            github_orgs=github_orgs,
            dorks=dorks,
            skip_ai=skip_ai,
        )
    )

    table = Table(title="Exposure — resumo")
    table.add_column("Tool")
    table.add_column("Severity")
    table.add_column("Title")
    for f in sorted(result.findings, key=lambda x: x.severity)[:30]:
        sev = f.ai_triage.adjusted_severity if f.ai_triage else f.severity
        table.add_row(f.source_tool, sev, f.title[:80])
    console.print(table)

    if result.errors:
        console.print(f"[yellow]Avisos:[/] {result.errors}")

    if result.report_path:
        console.print(f"\n[green]Relatorio:[/] {result.report_path.resolve()}")


@app.command()
def serve(
    host: Annotated[str, typer.Option()] = "0.0.0.0",
    port: Annotated[int, typer.Option()] = 8080,
) -> None:
    """Sobe a API REST (FastAPI + uvicorn)."""
    import uvicorn

    uvicorn.run("orchestrator.main:app", host=host, port=port, reload=False)


@app.command()
def bundle(
    scan_id: Annotated[str, typer.Argument(help="UUID do scan já executado")],
    out: Annotated[
        Path | None,
        typer.Option(help="Path do JSON output. Default: reports/scan-<id>/ai-bundle.json"),
    ] = None,
) -> None:
    """Gera AI Fix Bundle (JSON) pra outra IA consumir e patchar código."""
    import json
    from uuid import UUID

    from orchestrator.reporting.exporters.ai_bundle import build_bundle

    _setup_logging()
    scan_uuid = UUID(scan_id)

    data = asyncio.run(build_bundle(scan_uuid))
    out_path = out or settings.REPORTS_DIR / f"scan-{scan_id}" / "ai-bundle.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    n_vulns = len(data.get("vulnerabilities", []))
    counts = data["summary"]["counts_by_severity"]
    console.print(f"[bold green]AI Fix Bundle[/] gerado: [cyan]{out_path.resolve()}[/]")
    console.print(
        f"  schema={data['schema_version']}  vulns={n_vulns}  "
        f"crit={counts['critical']} high={counts['high']} med={counts['medium']}"
    )
    console.print(
        f"  patcher_auto={data['summary']['patchable_automatically_count']}  "
        f"review={data['summary']['needs_human_review_count']}"
    )
    console.print()
    console.print("[dim]Pra entregar a um patcher (Claude Code/Cursor):[/]")
    console.print(f"  cat {out_path} | <patcher>")


if __name__ == "__main__":
    app()
