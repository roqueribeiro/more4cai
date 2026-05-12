# Arquitetura — CAI Orchestrator

## Visão geral

CAI é uma plataforma de **pentest comercial** com triagem AI e dashboard em tempo real. 4 camadas:

1. **Scanners** — containers especializados (ZAP, Trivy, Greenbone, kali-toolbox) + binários no orchestrator (Nmap)
2. **Orchestrator** — FastAPI app que dispara scans, normaliza findings, chama AI, gera relatórios + AI Fix Bundle
3. **AI gateway** — litellm plugável entre Anthropic/OpenAI/Ollama/LM Studio + telemetria persistida em `AIRun`
4. **Observability** — Dashboard UI (HTML+CSS+JS sem build), SSE pra logs/phase em tempo real, ring buffer in-memory

```
┌────────────┐    ┌──────────────────┐    ┌────────────┐
│  Cliente   │ ─▶ │  Orchestrator    │ ─▶ │  Postgres  │
│ (CLI/REST/ │    │  (FastAPI +      │    │  scans,    │
│  UI)       │    │   StaticFiles)   │    │  findings, │
└────────────┘    └────────┬─────────┘    │  ai_runs   │
                           │              └────────────┘
            ┌──────────────┼──────────────┬─────────────┐
            ▼              ▼              ▼             ▼
       ┌─────────┐  ┌─────────────┐ ┌──────────┐ ┌─────────────┐
       │   arq   │  │  adapters   │ │ litellm  │ │  reports/   │
       │  worker │  │   (14)      │ │ gateway  │ │  HTML +     │
       └────┬────┘  └─────┬───────┘ └────┬─────┘ │  AI Bundle  │
            │             │               │       │  JSON       │
            ▼             ▼               ▼       └─────────────┘
       ┌────────┐    ┌────────┐    ┌──────────────┐
       │ Redis  │    │ ZAP    │    │ Anthropic /  │
       │        │    │ Trivy  │    │ OpenAI /     │
       │        │    │ Nmap   │    │ Ollama /     │
       │        │    │ ...    │    │ LM Studio    │
       └────────┘    └────────┘    └──────────────┘
                           │
                  ┌────────┴─────────┐
                  ▼                  ▼
          ┌───────────────┐  ┌──────────────────┐
          │ Dashboard UI  │  │  Observability   │
          │ /ui/          │  │  ring buffer     │
          │ (Tailwind+    │  │  + SSE stream    │
          │  Alpine+JS)   │  │  + AIRun DB      │
          └───────────────┘  └──────────────────┘
```

---

## Componentes

### Adapters (`orchestrator/adapters/`)

Cada scanner implementa `ScannerAdapter` Protocol em `base.py`:

```python
class ScannerAdapter(Protocol):
    name: str
    async def health(self) -> bool: ...
    async def start_scan(self, target, options) -> ScanHandle: ...
    async def poll(self, handle) -> ScanStatus: ...
    async def fetch_results(self, handle) -> RawResults: ...
    async def normalize(self, raw) -> list[Finding]: ...
```

**14 adapters implementados** — ver tabela em [README §7](../README.md#7-adapters-disponíveis).

**Princípios**:
- `health()` SEMPRE retorna `bool` (nunca lança)
- `start_scan()` é não-bloqueante (subprocess/HTTP async)
- `normalize()` produz `Finding` canônico — sem variantes
- Severity é heurística do scanner; AI ajusta depois em `ai_triage.adjusted_severity`

### Domain (`orchestrator/domain/`)

- **`schemas.py`** — Pydantic v2: `Finding`, `Target`, `AITriage`, `Severity`, `Confidence`, `AssetType`, etc. **Forma canônica** que todos os adapters produzem
- **`scrubber.py`** — regex PII/PCI antes do LLM externo (CPF, CNPJ, PAN com Luhn, JWT, AWS keys, etc.)
- **`dedup.py`** — heurística (`deduped_key` = `sha256(target.value::rule_id)[:32]`) + semântica opcional via LLM

**`deduped_key`** é determinístico — mesmo finding em runs diferentes tem mesma chave. Usado como base do `vulnerabilities[].id` no AI Fix Bundle (`uuid5(deduped_key)`) — patcher pode rastrear "o que já corrigi".

### AI gateway (`orchestrator/ai/`)

#### `gateway.py` — litellm wrapper

```python
async def complete(
    messages, *, model=None, response_format=None, cache_system=True,
    max_tokens=4096, temperature=0.2, api_base=None,
    purpose: str = "unknown",       # nova: rótulo da chamada (triage/dedup/...)
    scan_id: UUID | None = None,    # nova: associação à scan
    finding_count: int = 0,          # nova: telemetria
) -> str:
    ...
```

**Funcionalidades**:
- **Fallback automático** — primário falha (timeout/5xx/auth) → tenta `LLM_FALLBACK_MODEL` (sempre cloud)
- **Anthropic prompt caching** — system prompt grande marcado com `cache_control: ephemeral`
- **LM Studio quirk** — `response_format=json_object` é omitido quando `LLM_API_BASE` setado (LM Studio rejeita)
- **Telemetria persistida** — cada call grava `AIRun` no DB (model, latency_ms, prompt_tokens, completion_tokens, success, error)

#### `analyzer.py` — `triage_batch()`

Recebe `list[Finding]` em batches de 25 (configurável), chama `complete_json` por batch passando `purpose="triage"`. Output: `Finding.ai_triage` populado com `adjusted_severity`, `rationale`, `business_impact`, `suggested_remediation`, `owasp_top10`.

Skip default: findings com `severity=info` (custo desproporcional). Configurável via `skip_severities=set()`.

#### `agentic/cai_expert.py` — investigação profunda

Endpoint `POST /investigate/{finding_id}` com HITL (`dry_run=true` por default). Fallback Claude direto quando `cai-framework` não instalado.

#### `observability.py` — ring buffer + SSE

- `_LOG_BUFFER: deque[dict] (maxlen=1000)` — singleton em memória
- `log_processor` — structlog processor que appenda eventos ao buffer
- `_PHASE_BUFFER: dict[scan_id, dict]` — última atualização de fase por scan
- `emit_phase(scan_id, phase, progress)` — chamado pelo pipeline em transições
- `sse_stream(scan_id=None)` — async generator que streama logs novos + phase updates via Server-Sent Events

### Persistence (`orchestrator/persistence/`)

- SQLite (dev) ou Postgres (prod) via `DATABASE_URL`
- SQLModel: `TargetRow`, `ScanRow`, `FindingRow`, `AIRun` (4 tabelas)
- 3 migrations alembic:
  - `0001_initial` — schema base
  - `0002_remove_compliance_fields` — drop `audit_log`, `authorization_ref`, `contains_pci`
  - `0003_add_current_phase` — adiciona `ScanRow.current_phase` + `phase_progress` pra observability

**`AIRun`** — telemetria de cada chamada LLM:
```python
class AIRun:
    id: UUID
    scan_id: UUID | None
    purpose: str           # "triage" | "investigation" | "dedup" | "triage.fallback" | ...
    model: str             # "openai/qwen/qwen3.6-27b" | "anthropic/claude-opus-4-7" | ...
    prompt_tokens: int
    completion_tokens: int
    cache_creation_tokens: int
    cache_read_tokens: int
    latency_ms: int
    finding_count: int     # findings nesse batch
    success: bool
    error: str | None
    created_at: datetime
```

### API (`orchestrator/api/`)

8 routers REST, todos com `X-API-Token`:

| Router | Endpoints |
|---|---|
| `targets.py` | POST/GET `/targets` |
| `scans.py` | POST `/scans` (arq enqueue), GET `/scans/{id}`, GET `/scans` |
| `findings.py` | GET `/findings` (filtros), GET `/findings/{id}` |
| `reports.py` | GET HTML, **GET `/reports/{id}/ai-bundle`** ⭐, POST DefectDojo |
| `exposure.py` | POST `/exposure/scan` (OSINT) |
| `investigate.py` | POST `/investigate/{finding_id}` (CAI agentic, HITL) |
| `health.py` | **GET `/health/full`** ⭐ — agregador (Postgres/Redis/ZAP/LLM) |
| `ui.py` | **`/ui/api/*`** ⭐ — endpoints do dashboard + SSE |

`/health` (sem auth) — liveness simples.

### Frontend (`orchestrator/static/`)

Dashboard HTML+CSS+JS **sem build step**:
- `index.html` — Single Page com 4 abas (Dashboard, Scans, AI Calls, Logs)
- `cockpit.html` — Cockpit live por scan (timeline visual de fases + findings + AI calls + logs SSE)
- `app.js` — Alpine.js components, polling 3s, SSE pra logs/phase, Chart.js
- `styles.css` — polish minor

Servido via `app.mount("/ui", StaticFiles(...))`.

### Jobs (`orchestrator/jobs/`)

- **`pipelines.py`** — `run_scan()` síncrono. Atualiza `ScanRow.current_phase` em cada transição (`queued|nmap_running|zap_spider|dedup|ai_triage|persisting|reporting|done|failed`) e chama `emit_phase()` pra notificar SSE
- **`exposure.py`** — `run_exposure_scan()` (OSINT)
- **`queue.py`** + **`workers.py`** — arq (Redis-backed)

### Reporting (`orchestrator/reporting/`)

- **`renderer.py`** — Jinja2 templates (`report.html.j2` técnico, `executive.html.j2` resumo)
- **`exporters/ai_bundle.py`** ⭐ — gera AI Fix Bundle (schema 1.0.0). Usa `uuid5(deduped_key)` pra ID estável. Aplica `scrubber` antes de servir
- **`exporters/defectdojo.py`** — Generic Findings Import

---

## Fluxos

### Scan ativo

```
1. Cliente: POST /targets { value, criticality, contains_pii }
2. Cliente: POST /scans { target_id, scanners }
3. orchestrator: enfileira no arq → 202 Accepted
4. worker arq: pega job
   ├─ phase: queued    → atualiza ScanRow + emit_phase SSE
   ├─ phase: nmap_running → adapter.start_scan/poll/fetch/normalize
   ├─ phase: zap_running  → idem (com retry no scan_id=0)
   ├─ phase: dedup     → heuristic_dedup
   ├─ phase: ai_triage → triage_batch (batches de 25)
   │   └─ cada batch chama gateway.complete_json → AIRun gravada
   ├─ phase: persisting → ScanRow + FindingRow no DB
   ├─ phase: reporting  → render_html
   └─ phase: done | failed
5. Cliente:
   ├─ GET /reports/{scan_id}              → HTML técnico
   ├─ GET /reports/{scan_id}/ai-bundle    → JSON pra AI patcher
   └─ Dashboard UI mostra progresso em tempo real (cockpit)
```

### Scan OSINT

```
1. POST /exposure/scan { company_name, domains, dorks }
2. worker (run_exposure_scan):
   - GitHubExposure: dorks contra repos públicos → matches
   - paralelo: Gitleaks + Trufflehog nos top-N repos descobertos
   - paralelo: dnstwist em cada domínio (typosquats)
   - opcional: Shodan, Censys, SubdomainTakeover
   - AI triage filtra ruído (essencial em OSINT)
3. Relatório `reports/exposure-*.html`
```

### Live observability (SSE)

```
Browser EventSource → GET /ui/api/events?scan_id=X
                                          │
                                          ▼
                                    sse_stream(scan_id)
                                          │
                          ┌───────────────┼───────────────┐
                          ▼                               ▼
                   _LOG_BUFFER                      _PHASE_BUFFER
                   (deque 1000)                     (dict[scan_id])
                          ▲                               ▲
                          │                               │
              structlog log_processor              pipeline emit_phase()
              (cada log call appenda)              (cada transição)
                          ▲                               ▲
                          │                               │
                  todo orchestrator                  run_scan()
```

Frontend abre EventSource, recebe eventos `event: log` e `event: phase`. Reconnect automático.

---

## Dashboard UI

### Aba ◉ Dashboard

Polling 3s pra:
- `/health/full` — components Postgres/Redis/ZAP/LLM local/cloud
- `/ui/api/scans?limit=50` — últimos scans com fase atual
- `/ui/api/ai-runs?limit=100` — últimas chamadas LLM
- `/ui/api/ai-runs/stats` — agregações (total, p50/p95 latency, fallback rate, success rate, by_model)

Charts (Chart.js via CDN):
- **Doughnut** — distribuição de modelos usados
- **Stacked bar** — severity counts dos últimos 10 scans

### Aba ⚡ Scans

Tabela com `state`, `current_phase`, `phase_progress`, severity counts. Link pro **cockpit** de cada scan.

### Cockpit (`/ui/cockpit.html?scan_id=X`)

- **Timeline visual de fases** com ícones `✓ done | ⚡ running | ✗ failed | ○ pending`
- **Findings ao vivo** (poll 3s) ordenados por severity rank
- **AI calls deste scan** (filtrado por `scan_id`)
- **Live logs SSE** filtrados pelo scan
- **Botão de download AI Fix Bundle** quando `state=done`

### Aba ✦ AI Calls

Tabela de `AIRun`: timestamp, purpose, model, latência, tokens (in/out), success, error. **Útil pra ver se LM Studio está realmente sendo chamado** ou se foi pro fallback cloud.

### Aba ⌗ Logs

Stream SSE de todo log do orchestrator. Filtrável por `event`/`level`/qualquer texto.

---

## Compliance e privacy (genérico)

CAI removeu refs bancárias específicas (BACEN/LGPD/PCI) na transição banco→pentest comercial. O que **fica** é genérico:

- **`scrubber.py`** — PII redaction antes de mandar pro LLM externo (CPF, CNPJ, PAN, JWT, AWS keys). Útil pra cliente brasileiro independente de regulação
- **`X-API-Token`** — auth simples, suficiente pra orchestrator interno
- **`contains_pii` flag** — boa prática genérica pra rotear dados pessoais ao LLM local
- **Bundle passa por scrubber** antes de servir — snippets de request/response do cliente comercial não vazam credencial em arquivo entregável

---

## Limitações conhecidas

- **Bug ZAP `scan_id=0`** — corrigido com retry (`zap_adapter._start_spider_with_retry`)
- **Greenbone**: feed sync inicial 30min-3h, ~5GB
- **Ollama**: 32B q4 cabe em 24GB VRAM mas com pouco context (8-16k)
- **CAI agentic** (`cai_expert.py`) — fallback Claude funcional; integração total `cai-framework` é stub
- **DefectDojo**: Generic Findings Import — pode precisar ajuste de campos
- **Dashboard UI**: token via `?token=...` ou localStorage. OIDC fica como TODO
- **Live logs**: ring buffer in-memory reseta em restart do container (logs históricos em `docker logs`)
- **WebSocket bidirectional**: não implementado. Cancelamento de scan via REST `DELETE` (ainda TODO)

---

## Referências

- [README.md](../README.md) — overview + quickstart
- [docs/usage.md](usage.md) — cookbook (6 receitas)
- [docs/runbook.md](runbook.md) — operação dia-a-dia
- [docs/threat-model.md](threat-model.md) — atores, dados sensíveis
- [.claude/rules/](../.claude/rules/) — convenções por subsistema
