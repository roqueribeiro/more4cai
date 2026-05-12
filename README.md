# CAI — Continuous AI Security

> Vulnerability scanning + AI triage + AI Fix Bundle handoff to AI patchers (Claude Code, Cursor, Copilot).

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/release/python-3130/)
[![CI](https://github.com/roqueribeiro/more4cai/actions/workflows/ci.yml/badge.svg)](https://github.com/roqueribeiro/more4cai/actions/workflows/ci.yml)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

**Documentation in other languages:** [Português (Brasil)](README.pt-BR.md)

---

CAI is an open-source platform that orchestrates 15 security scanners (Nmap, OWASP ZAP, Nuclei, Trivy, Greenbone, Gitleaks, Trufflehog, dnstwist, Checkov, kube-bench, Shodan, Censys, GitHub Code Search, Subdomain Takeover, and a base Protocol), normalizes their output into a canonical `Finding` schema, and runs a privacy-aware AI triage step before exporting an **AI Fix Bundle JSON** that another AI agent (Claude Code, Cursor, Copilot) can consume to propose patches in the target codebase.

The goal: **close the loop between scan and fix** for regulated environments (banking, fintech, healthcare) where findings cannot leak to the public internet but human pentesters cannot scale to every codebase.

## Status

CAI is **alpha (pre-1.0)**. Interfaces and DB schema may break. Production use against real assets is gated by compliance checks documented in [SECURITY.md](SECURITY.md) and the threat model in [docs/threat-model.md](docs/threat-model.md).

## How it works

```
   Operator                                AI Patcher
   (CLI / REST / UI)                       (Claude Code, Cursor, ...)
        |                                          ^
        v                                          |
   +-------------------+      +----------------+   |
   | CAI Orchestrator  |----->| Canonical      |   |
   |  - 15 adapters    |      | Finding (v2)   |   |
   |  - PII scrubber   |      +-------+--------+   |
   |  - litellm AI     |              v            |
   |    triage         |      +----------------+   |
   |  - Audit log      |----->| AI Triage      |   |
   |    (append-only)  |      | (OWASP/CWE)    |   |
   +---------+---------+      +-------+--------+   |
             |                        v            |
             |                +----------------+   |
             |                | AI Fix Bundle  |---+
             |                | JSON (1.0.0)   |
             |                +----------------+
             v
   +-------------------+
   | HTML reports +    |
   | Dashboard UI      |
   +-------------------+
```

## Quickstart (5 minutes)

Prerequisites: Docker Desktop (WSL2 on Windows) or Docker Engine, 8 GB of free RAM, optionally a Claude/OpenAI API key.

```bash
git clone https://github.com/roqueribeiro/more4cai.git
cd more4cai
cp .env.example .env
# fill in APP_TOKEN, POSTGRES_PASSWORD, ZAP_API_KEY (any random strings)
# optional: ANTHROPIC_API_KEY or OPENAI_API_KEY

make build       # build the orchestrator image
make up          # bring up postgres + redis + orchestrator + worker + zap + lab
make migrate     # alembic upgrade head
make smoke       # E2E: scan Juice Shop and produce an HTML report
```

Open `http://127.0.0.1:8080/ui/` to see the dashboard, or `http://127.0.0.1:8080/docs` for the OpenAPI spec. All endpoints require the `X-API-Token` header you set in `.env`.

## Features

- **15 scanner adapters** following a single `ScannerAdapter` Protocol — easy to add new ones (see [CONTRIBUTING.md](CONTRIBUTING.md) and [`orchestrator/adapters/base.py`](orchestrator/adapters/base.py)).
- **Canonical `Finding` schema** with deduplication, severity, OWASP/CWE mapping, evidence, and remediation hints.
- **PII / PCI scrubber** that redacts CPF, CNPJ, card numbers, JWTs, AWS keys, and BR phone numbers *before* anything leaves the orchestrator.
- **AI triage via [litellm](https://github.com/BerriAI/litellm)** — works with Anthropic, OpenAI, OpenRouter, Ollama, and LM Studio behind a single configuration. Local models keep sensitive findings on-prem.
- **AI Fix Bundle JSON exporter (schema 1.0.0)** — designed for handoff to an AI patcher that proposes code changes against the scanned project.
- **Append-only audit log** enforced at both the application and the Postgres trigger layer.
- **HTML technical and executive reports** + optional DefectDojo export.
- **Modular Docker Compose** — pick the profiles you need (`default`, `scanners`, `lab`, `greenbone`, `obs`, `proxy`, `ai-agent`).

## Adapters

| Adapter | Scanner | Type |
|---|---|---|
| `nmap_adapter` | Nmap | Network |
| `zap_adapter` | OWASP ZAP | Web app (DAST) |
| `nuclei_adapter` | Nuclei | Templated vuln scan |
| `trivy_adapter` | Trivy | Container / IaC / FS |
| `checkov_adapter` | Checkov | IaC misconfig |
| `gitleaks_adapter` | Gitleaks | Secret scan |
| `trufflehog_adapter` | Trufflehog | Verified-secret scan |
| `dnstwist_adapter` | dnstwist | Typosquatting / domain perms |
| `kube_bench_adapter` | kube-bench | CIS Kubernetes |
| `greenbone_adapter` | Greenbone / OpenVAS | Network vuln |
| `shodan_adapter` | Shodan | Internet exposure (OSINT) |
| `github_exposure_adapter` | GitHub Search | Code / secret leaks |
| `censys_adapter` | Censys | Internet exposure (optional) |
| `subdomain_takeover_adapter` | subfinder + httpx + nuclei | Subdomain takeover |

## Deeper documentation

The full project documentation is currently in **Portuguese (Brazil)**. Translation help is very welcome — see issues tagged `good first issue` + `docs`.

- [README.pt-BR.md](README.pt-BR.md) — full feature walkthrough (PT-BR)
- [docs/architecture.md](docs/architecture.md) — internal layout
- [docs/runbook.md](docs/runbook.md) — operations, troubleshooting, common pitfalls
- [docs/threat-model.md](docs/threat-model.md) — threat model and compliance gates
- [docs/usage.md](docs/usage.md) — end-to-end usage examples
- [docs/testing.md](docs/testing.md) — test strategy

## Contributing

Issues and PRs are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) first. For security reports, follow [SECURITY.md](SECURITY.md) (private channel).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

CAI bundles or invokes third-party software under their respective licenses; see `NOTICE` and `pyproject.toml`.
