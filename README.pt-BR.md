# CAI — Continuous AI Security

> **Plataforma de pentest comercial com triagem AI e dashboard em tempo real.**
> 14+ scanner adapters (Nmap, ZAP, Nuclei, Trivy, Greenbone, gitleaks, trufflehog, dnstwist, GitHub/Shodan/Censys, Checkov, kube-bench) + AI triage via litellm (Claude/OpenAI/Ollama/LM Studio) + AI Fix Bundle JSON pra outra IA (Claude Code, Cursor, Copilot) consumir e propor patches no código.

**Documentação em outros idiomas:** [English](README.md)

---

## Sumário

1. [O que faz](#1-o-que-faz)
2. [Quickstart (5 min)](#2-quickstart-5-min)
3. [4 modos de uso](#3-4-modos-de-uso)
4. [Dashboard UI](#4-dashboard-ui)
5. [AI Fix Bundle](#5-ai-fix-bundle)
6. [LLM providers (litellm)](#6-llm-providers-litellm)
7. [Adapters disponíveis](#7-adapters-disponíveis)
8. [Self-heal e debug](#8-self-heal-e-debug)
9. [Troubleshooting](#9-troubleshooting)
10. [Estrutura do projeto](#10-estrutura-do-projeto)
11. [Limitações](#11-limitações)
12. [Contribuindo](#12-contribuindo)
13. [Referências](#13-referências)

---

## 1. O que faz

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Pipeline `scan → bundle → fix`                     │
└─────────────────────────────────────────────────────────────────────────┘

       Operador                                  Outra IA (Claude Code/
       (CLI/REST/UI)                             Cursor/Copilot/GPT)
            │                                            │
            ▼                                            │
   ┌──────────────────┐                                  │
   │  CAI Orchestrator │                                  │
   │  ┌─────────────┐ │   ┌──────────────────┐          │
   │  │  14 Scanner │─┼──▶│  Findings        │          │
   │  │  Adapters   │ │   │  canônicos       │          │
   │  └─────────────┘ │   └─────┬────────────┘          │
   │                   │         │                        │
   │  ┌─────────────┐ │         ▼                        │
   │  │  AI Triage  │ │   ┌──────────────────┐          │
   │  │ via litellm │─┼──▶│  AITriage        │          │
   │  │ (LM Studio/ │ │   │  + OWASP/CWE     │          │
   │  │  Anthropic) │ │   └─────┬────────────┘          │
   │  └─────────────┘ │         │                        │
   │                   │         ▼                        │
   │  ┌─────────────┐ │   ┌──────────────────┐          │
   │  │   Bundle    │─┼──▶│  ai-bundle.json  │──────────▶│
   │  │  Exporter   │ │   │  (schema 1.0.0)  │   patches  │
   │  └─────────────┘ │   └──────────────────┘            │
   │                   │                                   │
   │  Postgres + arq + Redis + ZAP + Trivy + …            │
   └──────────────────┘                                   │
            │                                              │
            ▼                                              ▼
    ┌──────────────────┐                       ┌──────────────────┐
    │  Dashboard UI    │                       │  Re-scan valida  │
    │  (real-time)     │                       │  fix             │
    └──────────────────┘                       └──────────────────┘
```

**Workflow típico de engagement comercial**:

1. Pentester recebe escopo escrito do cliente (URLs, IPs, repos públicos)
2. Dispara `make scan` ou `POST /scans` — pipeline normaliza tudo pra `Finding` canônico
3. AI triage ajusta severity por OWASP/CWE/contexto técnico (rodando em LM Studio local pra dados sensíveis ou Anthropic Cloud pra qualidade)
4. Saídas:
   - **HTML técnico** (`reports/scan-*.html`)
   - **Dashboard UI** (`http://127.0.0.1:8080/ui/`) — visibilidade em tempo real
   - **AI Fix Bundle JSON** (`/reports/{id}/ai-bundle`) — entregável pra outra IA patcher
5. Bundle é consumido por Claude Code/Cursor que propõe patches no código do cliente
6. Re-scan valida fix

---

## 2. Quickstart (5 min)

### Pré-requisitos
- **Docker Desktop** com WSL2 backend (Windows) ou **Docker Engine** (Linux)
- **8 GB RAM** livres (16 GB recomendado se rodar Greenbone)
- **GPU NVIDIA ≥8 GB VRAM** (opcional, para LM Studio local)
- **API key Anthropic** ou **OpenAI** (recomendado, pelo menos como fallback)

### Setup

```bash
git clone https://github.com/roqueribeiro/more4cai.git && cd more4cai
cp .env.example .env

# Gera secrets fortes
sed -i.bak "s/APP_TOKEN=.*/APP_TOKEN=$(openssl rand -base64 16)/" .env
sed -i.bak "s/ZAP_API_KEY=.*/ZAP_API_KEY=$(openssl rand -hex 16)/" .env
sed -i.bak "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -base64 12)/" .env
rm .env.bak

# (Opcional mas recomendado) Adicione pelo menos uma chave LLM:
# echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env

make build       # build da imagem orchestrator (~1min)
make up          # sobe stack
make migrate     # cria schema Postgres (alembic)
```

### Validação

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl -sf http://127.0.0.1:8080/health/full -H "X-API-Token: $TOKEN" | jq

# Esperado: overall=ok com postgres/redis/zap todos OK
```

### Abrir dashboard

```bash
echo "http://127.0.0.1:8080/ui/?token=$TOKEN"
```

Cole no browser. Você deve ver:
- 🟢 Stack health (Postgres/Redis/ZAP OK)
- ⚡ Aba "Scans" (vazia se primeira execução)
- ✦ Aba "AI Calls" (vazia)
- ⌗ Aba "Logs" streaming em tempo real

### Smoke test (E2E completo)

```bash
make smoke
```

Vai subir Juice Shop, disparar scan Nmap+ZAP, rodar dedup, e gerar relatório. Acompanhe pelo dashboard — aba **Scans** mostra o scan progredindo, click no scan-id pra abrir **cockpit live**.

---

## 3. 4 modos de uso

| Modo | Quando usar | Exemplo |
|---|---|---|
| **CLI** | Test ad-hoc, debug, scan sem AI | `make scan TARGET=http://juice-shop:3000` |
| **REST API** | Integração CI/CD, scan agendado | `POST /scans` (com header `X-API-Token`) |
| **Claude Code** | Operação interativa, troubleshooting | Skills auto-invocáveis ou `/comando` |
| **Dashboard UI** | Visibilidade em tempo real | `http://127.0.0.1:8080/ui/` |

### CLI

```bash
make scan TARGET=http://juice-shop:3000          # com AI triage
make scan-no-ai TARGET=http://juice-shop:3000    # sem AI (rápido)
make exposure EXTRA="--config-file config/exposure_targets.yml"  # OSINT
docker compose ... run --rm orchestrator bundle <scan_id>        # gera AI Fix Bundle
```

### REST API

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
BASE=http://127.0.0.1:8080

# 1. Cria target
TARGET_ID=$(curl -s -X POST $BASE/targets \
  -H "X-API-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"asset_type":"url","value":"http://juice-shop:3000","criticality":"medium"}' \
  | jq -r '.id')

# 2. Enfileira scan (worker arq processa)
SCAN_ID=$(curl -s -X POST $BASE/scans \
  -H "X-API-Token: $TOKEN" -H "Content-Type: application/json" \
  -d "{\"target_id\":\"$TARGET_ID\",\"scanners\":[\"nmap\",\"zap\"]}" \
  | jq -r '.id')

# 3. Acompanhar via dashboard
echo "http://127.0.0.1:8080/ui/cockpit.html?scan_id=$SCAN_ID&token=$TOKEN"

# 4. Quando state=done, baixar AI Fix Bundle
curl -s "$BASE/reports/$SCAN_ID/ai-bundle" -H "X-API-Token: $TOKEN" -o ai-bundle.json
```

Endpoints principais (todos com `X-API-Token`):

| Verbo | Path | O que faz |
|---|---|---|
| GET | `/health` | Liveness simples (sem auth) |
| GET | `/health/full` | Health agregador (Postgres/Redis/ZAP/LLM) |
| POST | `/targets` | Cria alvo |
| POST | `/scans` | Enfileira scan no arq → 202 |
| GET | `/scans/{id}` | Estado do scan |
| GET | `/findings` | Filtros: scan_id, severity, source_tool |
| GET | `/reports/{scan_id}` | HTML técnico |
| GET | `/reports/{scan_id}/ai-bundle` | **AI Fix Bundle JSON** |
| POST | `/reports/{id}/export/defectdojo` | Export pra DefectDojo |
| POST | `/exposure/scan` | OSINT scan |
| POST | `/investigate/{finding_id}` | CAI agentic (HITL) |
| GET | `/ui/api/*` | Endpoints do dashboard |

### Claude Code

10 skills auto-invocáveis + 13 slash commands + 4 subagents. Veja [§4](#4-dashboard-ui) e [§8](#8-self-heal-e-debug).

### Dashboard UI

Veja [§4](#4-dashboard-ui).

---

## 4. Dashboard UI

`http://127.0.0.1:8080/ui/?token=<APP_TOKEN>` — Tailwind + Alpine.js + Chart.js, sem build step.

### Aba ◉ Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│  CAI Dashboard                          [token] [🟢 healthy] │
├──┬──────────────────────────────────────────────────────────┤
│ ◉│ ## Stack health                                          │
│ ⚡│ [🟢 Postgres 4ms] [🟢 Redis 1ms] [🟢 ZAP 12ms]            │
│ ✦│ [🟢 LM Studio Qwen3.6-27B 200ms] [🟢 Anthropic key set]  │
│ ⌗│                                                          │
│  │ AI Calls: 47    Latência: 18.2s p50  Fallback: 4.2%      │
│  │                                                          │
│  │ ┌──────────────┐  ┌──────────────────────────┐         │
│  │ │ Modelos %    │  │ Severity por scan        │         │
│  │ │ (doughnut)   │  │ (stacked bar)            │         │
│  │ └──────────────┘  └──────────────────────────┘         │
└──┴──────────────────────────────────────────────────────────┘
```

Polling a cada 3s pra `/health/full`, `/ui/api/scans`, `/ui/api/ai-runs`, `/ui/api/ai-runs/stats`.

### Aba ⚡ Scans

Lista todos os scans com **fase atual** (`queued | nmap_running | zap_spider | dedup | ai_triage | persisting | reporting | done`) + counts de severity. Click no scan abre o **cockpit live**.

### Cockpit live (`/ui/cockpit.html?scan_id=X`)

```
┌────────────────────────────────────────────────────────────┐
│ Scan b5c610fd — http://juice-shop:3000          [running]  │
│ Iniciado: 14:32  Elapsed: 12m                              │
│                                                            │
│ ░░░░ Phase Timeline ░░░░                                   │
│ [✓ queued] [✓ nmap] [⚡ zap_spider 67%] [○ ai_triage]     │
│  ──→──     ──→──    ━━━━━━━            ┄┄┄┄┄              │
│                                                            │
│ ┌─────────────────────────────┬───────────────────────┐   │
│ │ Findings ao vivo (50/355)   │ AI Calls deste scan   │   │
│ │ medium  zap   X-Frame...    │ ✓ triage  18.2s       │   │
│ │ low     nmap  Open 80       │   qwen/qwen3.6-27b    │   │
│ │ ...                         │   2150p/487c · 25 fnd │   │
│ └─────────────────────────────┴───────────────────────┘   │
│                                                            │
│ ░░░░ Live logs (SSE) ░░░░                                  │
│ 14:34:12 INFO  zap.spider_started scan_id=14               │
│ 14:34:18 INFO  ai.triage_batch    batch=1 size=25          │
│ 14:34:36 INFO  ai_run.persisted   model=qwen latency=18.2s │
└────────────────────────────────────────────────────────────┘
```

- **Phase Timeline** atualiza via SSE quando o pipeline transiciona
- **Findings ao vivo** — poll 3s
- **AI Calls** — telemetria de cada chamada LLM (model, tokens, latência)
- **Live logs** — stream JSON estruturado em tempo real
- Quando `state=done`, aparece botão **Baixar bundle JSON**

### Aba ✦ AI Calls

Tabela com cada chamada LLM (purpose, model, latência, tokens in/out, success, error). Útil pra ver **se LM Studio está sendo realmente chamado** ou se o tráfego foi pro fallback cloud.

### Aba ⌗ Logs

Stream SSE de eventos do orchestrator. Filtrável por `event`/`level`. Reset no restart do container.

---

## 5. AI Fix Bundle

JSON estruturado (schema versionado 1.0.0) pra outra IA (Claude Code, Cursor, Copilot, GPT) consumir e propor patches.

### Gerar

```bash
# Pelo Claude Code
"gera bundle do scan X pra Cursor"        # invoca skill cai-handoff-fix

# Slash command
/bundle <scan_id>

# CLI
docker compose -f docker/compose.yml -f docker/compose.scanners.yml --env-file .env \
  run --rm orchestrator bundle <scan_id>

# REST API
curl "$BASE/reports/<scan_id>/ai-bundle" -H "X-API-Token: $TOKEN" -o ai-bundle.json
```

### Estrutura

```jsonc
{
  "schema_version": "1.0.0",
  "generated_at": "2026-04-29T14:00:00Z",
  "scan": { "id": "...", "scanners_executed": ["nmap","zap"] },
  "target": {
    "primary_value": "https://app.example.com",
    "tech_stack_hints": { "languages": ["python"], "frameworks": ["fastapi"] }
  },
  "summary": {
    "counts_by_severity": {"critical": 1, "high": 4, ...},
    "owasp_top10_2021": ["A01", "A03"],
    "top_cwes": ["CWE-89", "CWE-79"],
    "patchable_automatically_count": 7,
    "needs_human_review_count": 13
  },
  "vulnerabilities": [
    {
      "id": "uuid5(deduped_key)",   // estável entre runs
      "title": "SQL Injection in /users",
      "severity": "high",
      "patch_priority": 2,            // 1=urgente, 5=cosmético
      "classification": {
        "owasp_top10_2021": "A03:2021-Injection",
        "cwe": ["CWE-89"],
        "cvss_v3": { "score": 8.6, ... }
      },
      "instances": [{ "location": {...}, "evidence": {...} }],
      "remediation": {
        "summary": "Use parameterized queries",
        "patch_strategy": { "approach": "code_change", "confidence": "high" },
        "code_search_patterns": [{"language":"python","pattern":"execute\\(.*\\+"}],
        "before_after_examples": [{"language":"python","before":"...","after":"..."}]
      },
      "verification": {
        "method": "rerun_scanner",
        "rerun": { "scanner": "zap", "options": { "focused_endpoint": "/users" } }
      },
      "ai_triage": { "rationale": "...", "model_used": "..." }
    }
  ]
}
```

### Handoff pra Claude Code

Skill `cai-handoff-fix` produz 3 artefatos:
- `ai-bundle.json` — JSON completo
- `HANDOFF.md` — top 5 vulnerabilidades em markdown legível
- **Snippet pronto pra colar** no Claude Code/Cursor:

```
Eu te entreguei um AI Fix Bundle em ./ai-bundle.json (schema 1.0.0).

Por favor:
1. Leia o JSON e ordene as vulnerabilidades por patch_priority (1=urgente).
2. Para cada uma, use os code_search_patterns da remediation pra localizar o código vulnerável no repo.
3. Proponha um patch seguindo before_after_examples (formato git diff).
4. Não aplique automaticamente — abra um PR por vulnerability separadamente.
5. No fim, retorne: lista de patches propostos, arquivos tocados, e quais não conseguiu localizar.

Comece pelas críticas. Verificação fica por minha conta.
```

---

## 6. LLM providers (litellm)

Gateway único em [`orchestrator/ai/gateway.py`](orchestrator/ai/gateway.py) com:
- Fallback automático (primário cai → tenta `LLM_FALLBACK_MODEL`)
- Telemetria persistida em `ai_runs` (model, latência, tokens, success, fallback flag)
- Anthropic prompt caching
- LM Studio quirks tratados (`response_format=json_object` é omitido)

### 4 cenários (configurar no `.env`)

| Cenário | LLM_MODEL | LLM_API_BASE | LLM_API_KEY | + Key adicional |
|---|---|---|---|---|
| **A — Anthropic Cloud** | `anthropic/claude-opus-4-7` | (vazio) | (vazio) | `ANTHROPIC_API_KEY` |
| **B — LM Studio** ⭐ | `openai/qwen/qwen3.6-27b` | `http://host.docker.internal:1234/v1` | `lm-studio` | (opcional fallback) |
| **C — Ollama (compose)** | `ollama/qwen2.5:32b-instruct-q4_K_M` | `http://ollama:11434/v1` | `ollama` | — |
| **D — OpenAI Cloud** | `openai/gpt-4o` | (vazio) | (vazio) | `OPENAI_API_KEY` |

### Setup LM Studio (cenário B — recomendado pra dados sensíveis)

1. Baixar e instalar LM Studio: <https://lmstudio.ai/>
2. Search por `qwen3.6` ou `qwen2.5-coder` → download (q4_K_M, ~18GB pra 27B)
3. Aba **Developer** → carregar modelo → habilitar **Local Server** (porta 1234)
4. Editar `.env` com cenário B
5. `docker compose -f docker/compose.yml --env-file .env restart orchestrator worker`
6. Validar: `/dashboard` → aba health → `llm_local: ok`

### Debug LLM

```
"testa o LLM"        # invoca skill cai-llm-debug
"o LM Studio está sendo usado?"
```

Ou manual:
```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl -s "http://127.0.0.1:8080/ui/api/ai-runs/stats" -H "X-API-Token: $TOKEN" | jq
docker exec cai-postgres psql -U cai -d cai -c "
  SELECT created_at, purpose, model, latency_ms, success FROM ai_runs
  ORDER BY created_at DESC LIMIT 10"
```

---

## 7. Adapters disponíveis

14 scanner adapters seguindo `ScannerAdapter` Protocol em [`orchestrator/adapters/base.py`](orchestrator/adapters/base.py).

| Adapter | Categoria | Como roda | Dependência |
|---|---|---|---|
| `nmap` | Rede | subprocess | `nmap` no orchestrator container |
| `zap` | Web | HTTP API | `zaproxy/zap-stable` container |
| `nuclei` | Web/Rede | subprocess + JSONL | `nuclei` no kali-toolbox |
| `trivy` | Container/IaC | subprocess + server | `aquasec/trivy` container |
| `greenbone` | Rede | python-gvm GMP | stack Greenbone |
| `checkov` | IaC | subprocess + JSON | `checkov` no kali-toolbox |
| `kube_bench` | k8s | subprocess + JSON | `kube-bench` |
| `gitleaks` | OSINT/secrets | clone + subprocess | `gitleaks` no kali-toolbox |
| `trufflehog` | OSINT/secrets | subprocess | `trufflehog` no kali-toolbox |
| `dnstwist` | OSINT/typosquat | subprocess + JSON | `dnstwist` no kali-toolbox |
| `github_exposure` | OSINT | PyGithub API | `GITHUB_TOKEN` |
| `shodan` | OSINT | API REST | `SHODAN_API_KEY` |
| `censys` | OSINT | API REST | `CENSYS_API_*` |
| `subdomain_takeover` | OSINT | subfinder \| httpx \| nuclei | binários no kali-toolbox |

Adicionar novo: `"crie adapter pra wpscan"` (skill `cai-add-adapter` cuida) ou ler [`.claude/rules/scanners.md`](.claude/rules/scanners.md).

---

## 8. Self-heal e debug

### Skills auto-invocáveis (10)

| Skill | Trigger natural |
|---|---|
| `cai-scan` | "rode scan em http://...", "pentest no host X" |
| `cai-exposure` | "tem código vazado?", "scan OSINT", "typosquats" |
| `cai-triage` | "analisa findings do scan X", "monta resumo executivo" |
| `cai-investigate` | "investiga esse finding", "valida exploitability" |
| `cai-handoff-fix` | "gera bundle pra Claude Code", "exporta findings pro Cursor" |
| `cai-add-adapter` | "criar adapter pra ferramenta X" |
| `cai-stack-status` | "está tudo no ar?" |
| **`cai-self-heal`** | **"isso quebrou", "scan falhou", "investiga esse bug"** |
| **`cai-llm-debug`** | **"testa o LLM", "qual modelo tá sendo usado?"** |
| `cai-deploy` | só explícito |

### Slash commands (13)

`/up`, `/down`, `/build`, `/migrate`, `/test`, `/lint`, `/status`, `/logs`, `/smoke`, `/backup`, `/db-shell`, `/bundle <id>`, `/dashboard`

### Subagents (4)

- `security-auditor` — review com lente OWASP/pentester
- `adapter-author` — escreve novos ScannerAdapters
- `findings-analyst` — análise estatística agregada
- `fix-bundle-author` — enriquece bundles com patterns/exemplos

---

## 9. Troubleshooting

> Pra investigação detalhada: skill `cai-self-heal` faz diagnóstico automático.

| Sintoma | Causa provável | Fix |
|---|---|---|
| `ZAP responde 401 / API key incorrect` | `--env-file .env` não foi passado | Sempre usar `make` (já cobre) ou passar explícito |
| `relation 'targets' does not exist` | Migration não rodou | `make migrate` |
| `ai_runs` table vazia mas rodei scans | (a) usou `--skip-ai`, ou (b) migration 0003 faltando | Conferir; rodar sem flag |
| Bundle gerado vazio (só Nmap, sem AI) | Mesma coisa | Idem |
| LM Studio "não está sendo chamado" | `.env` sem `LLM_API_BASE` setado | Skill `cai-llm-debug` diagnostica |
| `scan_id=0 Bad Request` em ZAP | Bug pós `newSession` | Já corrigido com retry no `zap_adapter._start_spider_with_retry` |
| Container ZAP "unhealthy" mas funciona | Cosmético — sem healthcheck declarado | Ignorar |
| `host.docker.internal unreachable` | Linux puro precisa `extra_hosts` | Já no `compose.yml` |
| Dashboard `401 Unauthorized` | Token errado ou faltando | Adicionar `?token=...` na URL ou `X-API-Token` header |
| SSE desconecta a cada 30s | Proxy/firewall corta long-poll | OK pro MVP — reconexão automática |

Detalhes em [docs/runbook.md](docs/runbook.md).

---

## 10. Estrutura do projeto

```
cai/
├── CLAUDE.md                    # overview pro Claude Code
├── README.md                    # este arquivo
├── docs/
│   ├── usage.md                 # cookbook consolidado
│   ├── architecture.md          # arquitetura detalhada
│   ├── runbook.md               # operação dia-a-dia
│   └── threat-model.md
├── orchestrator/
│   ├── main.py                  # FastAPI + StaticFiles UI
│   ├── cli.py                   # cai scan/exposure/serve/bundle
│   ├── config.py                # pydantic-settings
│   ├── adapters/                # 14 ScannerAdapters
│   ├── ai/
│   │   ├── gateway.py           # litellm + AIRun telemetria
│   │   ├── analyzer.py          # triage_batch
│   │   ├── observability.py     # ring buffer logs + SSE
│   │   └── prompts/             # system prompts
│   ├── api/routers/             # 8 routers REST
│   ├── domain/                  # Finding canônico, scrubber, dedup
│   ├── jobs/                    # arq workers + pipelines + phase tracking
│   ├── persistence/             # SQLModel + 3 alembic migrations
│   ├── reporting/               # HTML + AI Fix Bundle exporter
│   └── static/                  # Dashboard HTML+CSS+JS (sem build)
├── docker/
│   ├── compose.yml + compose.scanners.yml + compose.lab.yml + ...
│   └── images/{orchestrator,kali-toolbox,cai-expert}/Dockerfile
├── tests/unit/                  # scrubber, schemas, dedup, compliance
├── scripts/                     # smoke, backup, ollama-bootstrap
├── .env.example
└── .claude/                     # 10 skills + 4 agents + 13 commands + 5 rules
```

---

## 11. Limitações

- **Bug ZAP `scan_id=0` pós-newSession** — corrigido com retry, mas se reset manual derrubar sessão durante scan, pode falhar
- **Dashboard sem auth visual** — token via `?token=...` na URL ou localStorage. OIDC fica como TODO
- **Live logs reset no restart** — ring buffer in-memory. Histórico fica em `docker logs`
- **CAI agentic (`cai_expert.py`)** — fallback Claude funcional; integração total com `cai-framework` é stub
- **Greenbone feed sync inicial** ~30min-3h, ~5GB
- **Mobile responsive** — UI funciona desktop; mobile sem tratamento
- **WebSocket bidirectional** — não implementado. Cancelamento de scan via REST `DELETE` (ainda TODO)
- **Tests E2E do UI** — apenas smoke manual no browser
- **Modelos de reasoning (Qwen 3.x, DeepSeek-R1)** consomem `max_tokens` em `<think>` — aumentar pra 8192+ se output vier vazio

---

## 12. Contribuindo

```bash
# Branch
git checkout -b feature/meu-adapter

# Pelo Claude Code (recomendado)
"crie adapter pra wpscan"   # skill cai-add-adapter

# Manualmente
# Veja .claude/rules/scanners.md
# Copie do adapter mais próximo (orchestrator/adapters/nuclei_adapter.py)
# Adicione teste em tests/unit/test_<nome>_adapter.py

# Validar
make test
make lint
python .claude/_validate.py    # estrutura .claude/

# Commit (Claude Code roda hooks: format-python automaticamente)
git add . && git commit -m "feat(adapters): add wpscan adapter"
```

### Convenções

- **Python 3.13**, type hints, `from __future__ import annotations`
- **Async-first** (FastAPI, adapters, persistence)
- **litellm é o ÚNICO ponto de entrada pra LLM** — não importar Anthropic/OpenAI SDK direto
- **Findings sempre `domain.schemas.Finding`** — não criar variantes
- **AIRun sempre populada** — passar `purpose=` e `scan_id=` em `complete()`/`complete_json()`

Detalhes: [CLAUDE.md](CLAUDE.md), [`.claude/rules/`](.claude/rules/), [docs/usage.md](docs/usage.md).

---

## 13. Referências

### Documentação interna
- [docs/usage.md](docs/usage.md) — cookbook consolidado (6 receitas)
- [docs/architecture.md](docs/architecture.md) — arquitetura detalhada
- [docs/runbook.md](docs/runbook.md) — operação dia-a-dia
- [docs/threat-model.md](docs/threat-model.md) — atores, dados sensíveis
- [CLAUDE.md](CLAUDE.md) — overview pro Claude Code

### Externa
- [OWASP ZAP](https://www.zaproxy.org/)
- [Nmap NSE](https://nmap.org/book/nse.html)
- [Greenbone Community Edition](https://greenbone.github.io/docs/)
- [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates)
- [litellm](https://docs.litellm.ai/) — gateway LLM unificado
- [LM Studio](https://lmstudio.ai/) — LLM local desktop
- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)
- [Claude Code](https://claude.com/claude-code)

### Frameworks de classificação
- OWASP Top 10 (2021)
- CWE — Common Weakness Enumeration
- CVSS v3.1
