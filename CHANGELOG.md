# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `orchestrator.audit.log_audit_event` — append-only audit logging applied to
  `POST /scans` and `POST /targets`. Backed by `audit_log` table reintroduced
  by migration `0004_restore_audit_compliance`. In Postgres, UPDATE/DELETE on
  `audit_log` are rejected by trigger.
- `orchestrator.domain.target_validator.validate_target_value` — rejects
  argv-injection attempts (values starting with `-`) and SSRF to private,
  loopback, link-local, and IMDS networks when `LAB_ONLY=true`. Honors
  `TARGET_ALLOWLIST` (hostname, IP, CIDR, or `*.domain`).
- New settings: `LAB_ONLY` (default `true`), `TARGET_ALLOWLIST` (CSV or JSON
  array, default empty), `REQUIRE_AUTH_REF` (default `false`). When enabled,
  `REQUIRE_AUTH_REF` forces every `POST /scans` to include an
  `authorization_ref` recorded in the audit log.
- Optional `cleanup(handle)` method on all 9 subprocess scanner adapters.
  Backed by `orchestrator.adapters._cleanup.cleanup_subprocess_handle`,
  called automatically by the pipeline in a `finally` block to drain orphan
  asyncio tasks and remove temp directories (H7 in the security audit).
- `DELETE /scans/{id}` (204) — permanently removes a scan and its dependents
  (`findings`, `ai_runs` via the `scan_id` FK). Audits `scan.delete` into the
  append-only `audit_log` **before** deleting.
- Test suite expanded from 24 to 56 tests:
  scrubber-in-triage coverage, `target_validator` H4/H5 cases, the cleanup
  helper, and a `run_scan` scan-id regression test.

### Changed

- `run_scan` AI triage now runs on **every** finding (`skip_severities=set()`),
  not just `medium+`. Hardened targets often yield only `info`/`low` findings;
  skipping them meant the AI never ran ("connected a key but it isn't using
  AI"). The AI triage is the value prop, so it always runs.
- `orchestrator.ai.analyzer._finding_to_compact` now applies `scrub()` to
  `title`, `description`, and `evidence_snippets` before any payload leaves
  the orchestrator. Previously the scrubber lived in `reporting/exporters`
  only, so AI triage received unredacted PII/PCI (C1 in the security audit;
  LGPD Art. 46 / PCI DSS Req. 3).
- `orchestrator.api.deps.require_token` uses `hmac.compare_digest` to mitigate
  token timing attacks.
- `orchestrator.api.routers.ui._ui_token` accepts `?token=` query parameter
  only on `/ui/api/events` (SSE has no header support). All other UI endpoints
  now require `X-API-Token` header to prevent token leakage via logs,
  Referer, and browser cache.
- `orchestrator.domain.scrubber._PHONE_BR` regex anchored with `(?<!\d)` /
  `(?!\d)` boundaries to stop greedy matches inside long numeric tokens
  (closes issue #6).
- `orchestrator.adapters.greenbone_adapter` uses `defusedxml` instead of
  `xml.etree.ElementTree` to mitigate XXE / billion-laughs in untrusted XML
  (H6 in the security audit).
- Bumped `litellm` from `>=1.55.0` to `>=1.70.0` (rate-limit / prompt-handling
  fixes, addresses CVE backlog).
- Bumped `authlib` from `>=1.3.2` to `>=1.7.0` (CVE-2024-37568 — OIDC
  implicit grant).
- Added `defusedxml>=0.7.1` runtime dependency.

### Fixed

- `run_scan` now updates the `scan_id` it was given (created by `POST /scans`,
  the id the UI/SSE watches) instead of minting a fresh `uuid4()`. Before, the
  results landed under a different id and the requested scan stayed `pending`
  forever in the UI. `_ensure_scan_row` upserts the existing row. Regression:
  `tests/unit/test_pipeline_scan_id.py`.

### Security

- Closes C1, C2, H1, H4, H5, H6, H7 from the internal v0.1 security audit.
- AI triage path is now PII/PCI-safe by default. Operators should re-validate
  their custom `LLM_API_BASE` (e.g., LM Studio) but the scrubber runs
  unconditionally regardless of provider.

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
