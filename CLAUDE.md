# CAI — Continuous AI Security

Plataforma open-source de análise de vulnerabilidade para ambientes regulados (banking, fintech, healthcare — alinhada com LGPD/PCI/OWASP). Combina ~15 scanner adapters (Nmap, ZAP, Nuclei, Trivy, Greenbone, gitleaks, trufflehog, dnstwist, GitHub/Shodan/Censys, Checkov, kube-bench) com triagem AI híbrida (Claude/OpenAI via API + Ollama/LM Studio local) num orchestrator FastAPI + arq + Postgres.

## Comandos rápidos

```bash
make build           # build da imagem orchestrator
make up              # sobe stack (orchestrator + worker + db + redis + ollama + zap + lab)
make migrate         # alembic upgrade head
make smoke           # E2E: scan no Juice Shop e gera HTML
make test            # pytest
make scan TARGET=... # CLI síncrono
make down            # desce tudo
```

API REST: `http://127.0.0.1:8080` com header `X-API-Token`. Docs em [docs/runbook.md](docs/runbook.md).

## Arquitetura

- **`orchestrator/adapters/`** — 15 adapters seguindo `ScannerAdapter` Protocol (`base.py`)
- **`orchestrator/domain/`** — `Finding` canônico Pydantic, `scrubber.py` PII/PCI, `dedup.py`
- **`orchestrator/ai/`** — gateway litellm + AIAnalyzer + agentic (CAI framework opt-in)
- **`orchestrator/api/`** — FastAPI routers (targets, scans, findings, reports, exposure, investigate, audit)
- **`orchestrator/jobs/`** — arq workers + pipelines síncronos
- **`orchestrator/persistence/`** — SQLModel (SQLite dev, Postgres prod) + alembic
- **`orchestrator/audit/`** — append-only log (DB + arquivo)
- **`orchestrator/reporting/`** — HTML técnico + executivo + DefectDojo export

## Convenções de código

- **Python 3.13**, type hints em TUDO, `from __future__ import annotations` no topo
- **Async-first** — adapters/api/persistence são `async def`
- **Pydantic v2** pra schemas; `SQLModel` pra DB
- **structlog** pra logs (JSON em prod)
- **litellm** é o ÚNICO ponto de entrada pra LLM (não usar OpenAI/Anthropic SDK direto)
- **Adapters** seguem `ScannerAdapter` Protocol — implementar `health/start_scan/poll/fetch_results/normalize`
- **Findings** são SEMPRE `orchestrator.domain.schemas.Finding` — não criar variantes
- **Severity** ajustada por contexto vai em `Finding.ai_triage.adjusted_severity`, NÃO sobrescrever `Finding.severity`

## Compliance gates (ambientes regulados)

Pré-requisitos NÃO-NEGOCIÁVEIS pra qualquer scan ativo em produção:

1. `LAB_ONLY=true` (default em dev) bloqueia hosts fora da `TARGET_ALLOWLIST`
2. `REQUIRE_AUTH_REF=true` (prod) força `authorization_ref` em todo `POST /scans`
3. `scrubber.py` redaciona PII/PCI antes do LLM externo (LGPD Art. 46 / GDPR)
4. `audit_log` é append-only via trigger Postgres — nunca usar UPDATE/DELETE
5. Antes de rodar contra ativo real: autorização formal por escrito + janela acordada

Ferramentas explicitamente **excluídas da v1 em prod** sem aprovação dedicada: Metasploit (blast radius alto), BugTraceAI (lock-in OpenRouter).

## Antes de fazer mudanças

- **Adapter novo**: usar skill `cai-add-adapter` ou agent `adapter-author`. Sempre normalizar pra `Finding` canônico, sempre adicionar `health()`, sempre testar com fixture.
- **Mudança em `scrubber.py`**: requer review do DPO (LGPD compliance). Não relaxar regex sem motivo documentado.
- **Mudança em `audit/logger.py`**: NUNCA permitir UPDATE/DELETE em `audit_log`. Trigger no Postgres é proteção em camada — código não pode ser permissivo.
- **Mudança em `api/deps.py`**: auth muda postura de segurança. Discutir antes; nunca remover `require_token` de endpoint que existe.

## Common pitfalls

- **`AsyncSession.exec`** — usar `from sqlmodel.ext.asyncio.session import AsyncSession`, não SQLAlchemy puro
- **`datetime` sem tz** — sempre `datetime.now(UTC)`; em SQLModel sempre `sa_type=DateTime(timezone=True)`
- **`docker compose --env-file`** — `-f docker/compose.yml` muda project-dir; passar `--env-file .env` explícito
- **Multi-statement SQL no asyncpg** — quebrar `op.execute` em chamadas separadas
- **`field_validator(mode="before")`** — não dispara com default vazio. Use `model_validator(mode="after")`

## Testes

```bash
pytest                              # todos
pytest tests/unit/test_scrubber.py  # alvo específico
pytest --cov=orchestrator           # com cobertura
```

Test alvos vulneráveis no profile `lab`: Juice Shop (3000), DVWA (8000), WebGoat (8081/9090).

## Quando algo der errado

Antes de "consertar" algo no orchestrator, verifique se não é problema de infra:
1. `make ps` — containers rodando?
2. `docker logs cai-zap` — ZAP responde?
3. `docker exec cai-postgres psql -U cai -d cai -c '\dt'` — tabelas criadas?
4. `make migrate` rodou?

Bugs históricos comuns estão em [docs/runbook.md#troubleshooting](docs/runbook.md).
