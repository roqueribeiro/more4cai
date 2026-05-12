# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-11

### Added
- Initial public release of CAI (Continuous AI Security).
- FastAPI orchestrator + arq worker queue + Postgres persistence + Redis broker.
- 15 scanner adapters following the `ScannerAdapter` Protocol:
  Nmap, OWASP ZAP, Nuclei, Trivy, Checkov, Gitleaks, Trufflehog, dnstwist,
  kube-bench, Greenbone/OpenVAS, Shodan, GitHub Code Search, Censys,
  Subdomain Takeover (subfinder + httpx + nuclei), and a base Protocol.
- Canonical `Finding` schema (Pydantic v2) with dedup heuristics.
- PII / PCI scrubber that redacts CPF, CNPJ, PAN, JWT, AWS keys, and BR phone
  numbers before any prompt leaves the orchestrator.
- AI triage gateway via `litellm` supporting Anthropic, OpenAI, Ollama,
  LM Studio, and OpenRouter as a single backend abstraction.
- AI Fix Bundle JSON exporter (schema 1.0.0) for handoff to AI patchers
  (Claude Code, Cursor, Copilot).
- HTML technical and executive reports + optional DefectDojo export.
- Append-only audit log enforced both at the application and Postgres-trigger
  layer.
- Modular Docker Compose profiles: `default`, `scanners`, `lab`,
  `greenbone`, `obs`, `proxy`, `ai-agent`.
- Alembic migrations and SQLModel async support (SQLite for dev, Postgres
  for prod).
- `lab` profile with intentionally vulnerable test targets
  (Juice Shop, DVWA, WebGoat).
- Developer ergonomics: `make build/up/migrate/smoke/test/lint/down`, CLI
  via Typer (`cai`), structured logs via structlog.

### Security
- LGPD-aware compliance gates: `LAB_ONLY`, `TARGET_ALLOWLIST`,
  `REQUIRE_AUTH_REF`, mandatory `authorization_ref` for active scans in
  production mode.

[Unreleased]: https://github.com/roqueribeiro/more4cai/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/roqueribeiro/more4cai/releases/tag/v0.1.0
