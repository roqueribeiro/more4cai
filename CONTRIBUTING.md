# Contributing to CAI

Thanks for considering a contribution! CAI is in **alpha** and benefits from issues, PRs, new scanner adapters, AI prompt improvements, documentation, and translations alike.

Before opening a PR, please read the sections below — most reviews stall on items that are documented here.

## Code of Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By contributing you agree to uphold it.

## Found a vulnerability?

**Do not** open a public issue. Follow [SECURITY.md](SECURITY.md) — use GitHub Security Advisories.

## Ways to contribute

- **New scanner adapter** — easiest high-impact contribution. See `Adding an adapter` below.
- **Bug fix** — open an issue first only if the fix is non-trivial.
- **Feature** — open a GitHub issue using the *Feature Request* template to discuss design before coding.
- **AI prompt / triage rule** — see `orchestrator/ai/prompts/` and explain in the PR description what you observed before/after.
- **Documentation / translation** — README, runbook, threat-model, architecture. Bilingual PT-BR/EN PRs welcome.
- **Tests** — current coverage is light. Adding unit tests to adapters or API routers is always appreciated.

## Development setup

Prerequisites:

- Python 3.13
- Docker Desktop (WSL2 on Windows) or Docker Engine + Compose v2
- `make` (Linux/macOS native; on Windows use WSL or `gnumake`)
- At least 8 GB of free RAM (16 GB if you run the `greenbone` profile)

Clone and bootstrap:

```bash
git clone https://github.com/roqueribeiro/more4cai.git
cd more4cai
cp .env.example .env
# fill in at least APP_TOKEN, POSTGRES_PASSWORD, ZAP_API_KEY (any random strings)

make build       # build the orchestrator image (~5 min first time)
make up          # bring up postgres + redis + orchestrator + worker + zap + lab
make migrate     # alembic upgrade head
make smoke       # E2E: scan Juice Shop, produce HTML report in reports/
```

If the smoke test passes, your environment is good.

For a tighter inner loop without Docker (unit tests / linting only):

```bash
pip install -e ".[dev]"
pytest
ruff check orchestrator tests
mypy orchestrator
```

## Coding conventions

These are enforced in review and (most) by CI:

- **Python 3.13**, full type hints, `from __future__ import annotations` at the top of every module
- **Async-first** — adapters, API handlers, and persistence are `async def`
- **Pydantic v2** for schemas, `SQLModel` for DB models
- **structlog** for logging (JSON in prod, plain in dev)
- **litellm** is the *only* entry point to any LLM. Do **not** import `anthropic` or `openai` directly.
- **Findings** are always `orchestrator.domain.schemas.Finding`. No adapter-specific variants.
- **Severity** adjusted by AI context goes in `Finding.ai_triage.adjusted_severity`. Never overwrite `Finding.severity`.
- **Datetimes** are always `datetime.now(UTC)` and stored with `sa_type=DateTime(timezone=True)`.

Lint and type-check before pushing:

```bash
make lint     # ruff + mypy
pytest        # unit tests
```

## Adding an adapter

Adapters live in [`orchestrator/adapters/`](orchestrator/adapters/) and implement the `ScannerAdapter` Protocol defined in [`base.py`](orchestrator/adapters/base.py).

Minimum checklist for a new adapter:

1. Implement `health()`, `start_scan()`, `poll()`, `fetch_results()`, `normalize()`.
2. Normalize raw output into the canonical `Finding` schema (`orchestrator/domain/schemas.py`).
3. Add a unit test under `tests/unit/` using a static fixture of the scanner's raw output. No live network calls in tests.
4. Update [`README.md`](README.md) / [`README.pt-BR.md`](README.pt-BR.md) adapters table.
5. If the adapter needs an external service, add it to [`docker/`](docker/) (compose profile preferred) and document it in `.env.example`.
6. If the adapter calls an external API with a key, the key must come from `pydantic-settings`; never hard-code.

If you use Claude Code, the [`cai-add-adapter`](.claude/skills/cai-add-adapter/SKILL.md) skill scaffolds most of this.

## Modifying sensitive areas

Some files have extra review requirements because they affect compliance/security posture:

- **`orchestrator/domain/scrubber.py`** — regex changes need a justification in the PR description. Do not relax patterns without explaining the false-positive that motivated the change.
- **`orchestrator/audit/logger.py`** — the audit log is append-only. Never introduce code paths that `UPDATE` or `DELETE` from `audit_log`. The Postgres trigger is a safety net, not a license to relax the application layer.
- **`orchestrator/api/deps.py`** — authentication code. Never remove `require_token` from an endpoint that already has it. Discuss design in an issue first.

## PR workflow

1. Fork the repo and create a branch off `main`. Name it descriptively (`adapter/wapiti`, `fix/zap-timeout`, `docs/en-translation`).
2. Make focused commits. Avoid bundling refactors with feature work.
3. Add or update tests.
4. Update [`CHANGELOG.md`](CHANGELOG.md) under `[Unreleased]`. Use the categories: Added / Changed / Deprecated / Removed / Fixed / Security.
5. Sign your commits with a [DCO `Signed-off-by:` line](https://developercertificate.org/) (`git commit -s`). This affirms you wrote the change and can submit it under Apache 2.0.
6. Open a PR using the template. Fill in the checklist.
7. CI must be green. Address review comments by pushing additional commits — we squash on merge, so don't worry about a messy local history.

## Issue triage labels

- `good first issue` — small, well-scoped, lower context
- `help wanted` — we'd love a PR
- `adapter` — adding/improving a scanner integration
- `ai` — anything in `orchestrator/ai/`
- `compliance` — scrubber, audit log, allowlist, auth-ref logic
- `docs` — README, runbook, threat-model
- `breaking` — touches a public API or DB migration

## Releasing (maintainers only)

1. Bump the version in [`pyproject.toml`](pyproject.toml).
2. Move `[Unreleased]` items in [`CHANGELOG.md`](CHANGELOG.md) under the new version + date.
3. Tag: `git tag -s vX.Y.Z -m "vX.Y.Z"` (signed tag), `git push --tags`.
4. Create a GitHub Release from the tag, copy the CHANGELOG section into the body.

## Questions?

Open a [Discussion](https://github.com/roqueribeiro/more4cai/discussions) (preferred for design questions) or an issue.
