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

Skip: o default do `triage_batch` pula `severity=info` (custo desproporcional), mas **o pipeline (`run_scan`) passa `skip_severities=set()` — tria TODO finding**. Razão: alvos endurecidos (ex.: um domínio de produção bem configurado) rendem só achados `info`/`low`; pular eles fazia a IA nunca rodar ("conectei a chave e ela não usou IA"). A triagem por IA é a proposta de valor — então ela sempre roda. Configurável via `skip_severities`.

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
- SQLModel — **5 tabelas**: `TargetRow` (`targets`), `ScanRow` (`scans`), `AuditLogRow` (`audit_log`), `FindingRow` (`findings`), `AIRun` (`ai_runs`)
- **4 migrations alembic**:
  - `0001_initial` — schema base (já inclui `audit_log` + trigger de imutabilidade)
  - `0002_remove_compliance_fields` — dropa `audit_log`/trigger + `authorization_ref` + `contains_pci` (transição banco→pentest comercial)
  - `0003_add_current_phase` — `ScanRow.current_phase` + `phase_progress` (observability)
  - **`0004_restore_audit_compliance`** — **RESTAURA** o `audit_log` append-only (function `audit_log_immutable()` + trigger `audit_log_no_update`) + `authorization_ref`. A camada de compliance voltou como pré-requisito do uso enterprise/regulado (ver §Integração RoqueOS e §Segurança & Compliance)

**`AuditLogRow`** (`audit_log`) — trilha de auditoria **imutável append-only**:

```python
class AuditLogRow:
    id: UUID
    action: str               # "scan.create" | "scan.delete" | ...
    actor: str | None         # quem disparou (string hoje; vira identidade na Fase RBAC)
    resource_type: str        # "scan" | "target" | ...
    resource_id: UUID | None
    authorization_ref: str | None   # ticket/aprovação formal do engagement
    request_body: dict | None
    metadata: dict | None
    created_at: datetime
```

Imutabilidade no **nível do banco** (não só app): a function `audit_log_immutable()` + trigger `audit_log_no_update` (Postgres, `BEFORE UPDATE`) **rejeitam qualquer UPDATE** na tabela. SQLite (dev) ignora o trigger. Toda ação sensível (`scan.create`, `scan.delete`) grava aqui ANTES de mutar o recurso — ver `orchestrator/audit/logger.py` (`log_audit_event`).

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

| Router           | Endpoints                                                                                                                                            |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `targets.py`     | POST/GET `/targets`                                                                                                                                  |
| `scans.py`       | POST `/scans` (arq enqueue), GET `/scans/{id}`, GET `/scans`, **DELETE `/scans/{id}`** (204; audita `scan.delete` e apaga findings + AI runs por FK) |
| `findings.py`    | GET `/findings` (filtros), GET `/findings/{id}`                                                                                                      |
| `reports.py`     | GET HTML, **GET `/reports/{id}/ai-bundle`** ⭐, POST DefectDojo                                                                                      |
| `exposure.py`    | POST `/exposure/scan` (OSINT)                                                                                                                        |
| `investigate.py` | POST `/investigate/{finding_id}` (CAI agentic, HITL)                                                                                                 |
| `health.py`      | **GET `/health/full`** ⭐ — agregador (Postgres/Redis/ZAP/LLM)                                                                                       |
| `ui.py`          | **`/ui/api/*`** ⭐ — endpoints do dashboard + SSE                                                                                                    |

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

## Segurança & Compliance

> A camada de compliance foi **removida** na transição banco→comercial (migration `0002`) e **restaurada** (migration `0004`) ao produtizar o engine sob o RoqueOS (RoqueShield) para uso enterprise/regulado. Os controles abaixo estão **ativos** e são um diferencial — a maioria das ferramentas de pentest não tem trilha imutável nem scrubber nativo.

**Controles ativos (com referência):**

- **Trilha de auditoria imutável** — tabela `audit_log` + trigger Postgres `audit_log_no_update` (function `audit_log_immutable()`, `BEFORE UPDATE` rejeita qualquer alteração). Toda ação sensível grava ANTES de mutar o recurso. `orchestrator/audit/logger.py`.
- **Validação de alvo / escopo autorizado** — `orchestrator/domain/target_validator.py`: **allowlist** (`TARGET_ALLOWLIST`), bloqueio de **SSRF / rede privada / loopback** (`LAB_ONLY`), e anti-**injeção de argv** (impede que um "alvo" carregue flags pro scanner).
- **Referência de autorização** — `REQUIRE_AUTH_REF=true` exige `authorization_ref` (ticket/aprovação) em todo scan; o valor entra no `audit_log` (rastreabilidade do engagement).
- **PII/PCI scrubber** — `orchestrator/domain/scrubber.py`: redação de CPF, CNPJ, PAN (com Luhn), JWT, chaves AWS, telefone BR **antes** de qualquer LLM externo. O **AI Fix Bundle também passa pelo scrubber** antes de ser servido (snippets de request/response não vazam credencial no entregável).
- **Soberania de dados (LGPD by design)** — com `LLM_API_BASE` (LM Studio/Ollama) os findings **nunca saem da infra do cliente**: triagem por IA 100% on-prem. O scrubber é a 2ª linha de defesa quando um LLM cloud é usado.
- **AuthN — identidade + RBAC** (`orchestrator/api/deps.py` + `orchestrator/domain/roles.py`): `get_principal` resolve 3 credenciais — `X-API-Token` (serviço OU usuário) e `Authorization: Bearer` (sessão OIDC, ver bullet SSO). Dois caminhos no header `X-API-Token` — (1) **token de serviço** (`APP_TOKEN`, comparação timing-safe via `hmac.compare_digest`, sem hit no DB) que mapeia para um `Principal` de serviço **ADMIN** (é o que a integração RoqueShield injeta — backward-compatible); (2) **token por-usuário** (`UserRow`, hash SHA-256, token em claro mostrado uma vez) que resolve para a identidade real (id/email) + o papel do usuário. Na camada RoqueOS, o token de serviço é guardado **criptografado (AES)** pelo `roqueos-server` e o browser nunca o vê (ver §Integração RoqueOS).
- **RBAC — papéis + permissões** (`orchestrator/domain/roles.py`): 4 papéis (`admin`/`operator`/`auditor`/`viewer`) × permissões granulares (`users:manage`, `scans:run`, `scans:read`, `audit:read`, `config:manage`), com **segregação de funções** (operator dispara mas não lê o audit; auditor lê tudo + audit mas não dispara). Gate `require_permission(perm)` aplicado em todos os routers de scans/targets/findings/reports/exposure + o router admin `/users`. O `actor` do `audit_log` agora é a **identidade autenticada** (email do usuário ou `service@local`), não mais string livre.

- **SSO / OIDC** (`orchestrator/api/routers/auth.py` + `orchestrator/auth/`): login via IdP (Entra ID / Keycloak / Okta) — `GET /auth/login` → IdP → `GET /auth/callback` valida o ID token via **authlib** (assinatura via JWKS + nonce + aud + exp), faz **find-or-provision** do `UserRow` (por `idp_subject`, depois `email`; novo = papel `OIDC_DEFAULT_ROLE`, fail-closed = viewer), audita `user.login`, e emite uma **sessão JWT** (HS256, `SESSION_TTL_HOURS`). O cliente envia `Authorization: Bearer <jwt>`; o `get_principal` valida a sessão e **re-busca o usuário no DB** (papel/ativo correntes → revoga na hora ao desativar). Habilitado só quando `OIDC_ISSUER`+`CLIENT_ID`+`CLIENT_SECRET` setados (senão `/auth/*` → 503). `GET /auth/me` devolve a identidade corrente.

**Lacuna consciente (roadmap de identidade):** RBAC + usuários nomeados + tokens por-usuário + **SSO OIDC** estão **construídos e testados** (migrations `0005`; 25 testes em `test_rbac.py` + `test_auth_principal.py` + `test_session.py` + `test_provisioning.py`). Falta **multi-tenancy** (isolamento por org/projeto) e **scanning autenticado** (sessão/cookie/bearer no alvo + import OpenAPI) — os próximos P0 do roadmap.

---

## Integração RoqueOS (RoqueShield)

O more4cai (engine "CAI") é embarcado no **RoqueOS** como a feature **admin-only RoqueShield** — mesmo padrão dos módulos Agent/Android/Windows: opt-in, container-backed, proxy admin-gated. Arquitetura da integração:

```
RoqueOS Frontend (Vue) — app "RoqueShield" (ROSPentest.vue, admin-only)
   │  REST + SSE via apiService → roqueos-server (session-token, ADMIN-gated)
   ▼
roqueos-server (NestJS) — módulo `pentest`
   ├─ provisiona o STACK more4cai (reusa o motor de Compose Stacks)
   ├─ guarda APP_TOKEN + chaves de IA CRIPTOGRAFADOS (AES, ENCRYPTION_KEY)
   ├─ proxy reverso  ALL /pentest/api/* → orchestrator:8080  (injeta X-API-Token; o browser NUNCA vê o token)
   ├─ pipa SSE (text/event-stream) pro progresso ao vivo
   └─ @RequirePermission(ADMIN) em tudo
   │  dockerode → sobe a stack na roqueos-network
   ▼
stack more4cai: orchestrator + worker + postgres + redis + zap + trivy  (+ greenbone/ollama opt-in)
```

- **Modelo de auth:** o RoqueOS gera/guarda o `APP_TOKEN` do more4cai criptografado em repouso e injeta `X-API-Token` em cada request proxiado. O gate real é `ApiKeyGuard` + `@RequirePermission(ADMIN)` + o app `adminOnly` no front; o browser autentica por **session-token** curto (nunca apiKey na URL).
- **Config de IA guiada:** a aba **IA** lista os modelos reais por chave (`POST /pentest/ai/models` — bate no `/models` de cada provider server-side; as chaves nunca vão pro browser) e os campos de modelo viram **select**.
- **Relatórios abrem nas ferramentas nativas do RoqueOS:** md/json/csv no Editor de Texto, HTML no Navegador — nunca `window.open`/download (não escapam o OS).
- **UX nativa:** dashboard (postura de segurança + cards de scan), novo scan (com confirmação de autorização + `authorization_ref`), **stepper de fases ao vivo via SSE**, findings por severidade, e os 4 formatos de relatório (PDF/MD/JSON-AI-Bundle/CSV).
- Detalhe normativo no RoqueOS: `roqueos-front/.claude/rules/` (módulo `pentest`) + memória `roqueshield-pentest-platform`.

---

## Limitações conhecidas

- **Identidade:** RBAC + usuários + tokens por-usuário + **SSO OIDC** construídos; falta **multi-tenancy** (isolamento por org/projeto) e **scanning autenticado** — ver §Segurança & Compliance.
- **Scanning não-autenticado:** ZAP/Nuclei testam só a superfície exposta; falta scan **credenciado/autenticado** (sessão/cookie/bearer, import OpenAPI/Postman) — o maior gap pra app de banco (risco atrás do login).
- **One-shot:** sem agendamento/scan contínuo nem diff entre execuções (só correlação intra-scan via `dedup`).
- **Escala:** docker-compose single-host, adapters em sequência no pipeline — sem scan distribuído/horizontal.
- **Bug ZAP `scan_id=0`** — corrigido com retry (`zap_adapter._start_spider_with_retry`).
- **Greenbone:** feed sync inicial 30min-3h, ~5GB. **Ollama:** 32B q4 cabe em 24GB VRAM mas com context curto (8-16k).
- **CAI agentic** (`cai_expert.py`) — fallback Claude funcional; integração total `cai-framework` é stub.
- **DefectDojo:** Generic Findings Import — pode precisar ajuste de campos.
- **Live logs (SSE in-process):** o ring buffer é do processo do **orchestrator**; logs do **worker** (onde rodam os scanners) não chegam ao SSE — o RoqueShield deriva uma trilha de log das transições de fase. Histórico em `docker logs`.

---

## Referências

- [README.md](../README.md) — overview + quickstart
- [docs/usage.md](usage.md) — cookbook (6 receitas)
- [docs/runbook.md](runbook.md) — operação dia-a-dia
- [docs/threat-model.md](threat-model.md) — atores, dados sensíveis
- [.claude/rules/](../.claude/rules/) — convenções por subsistema
