# CAI — Guia de uso prático

Cookbook consolidado. Para arquitetura, ver [architecture.md](architecture.md).
Para troubleshooting, ver [runbook.md](runbook.md) ou usar a skill `cai-self-heal`.

---

## Índice

1. [Setup inicial (5 min)](#1-setup-inicial-5-min)
2. [3 modos de invocação](#2-3-modos-de-invocação)
3. [Receita 1 — Scan local com LM Studio](#receita-1--scan-local-com-lm-studio-do-zero-ao-bundle)
4. [Receita 2 — Scan REST API com triage AI](#receita-2--scan-rest-api-com-triage-ai)
5. [Receita 3 — OSINT em domínio público](#receita-3--osint-em-domínio-público)
6. [Receita 4 — Handoff bundle pra Claude Code/Cursor](#receita-4--handoff-bundle-pra-claude-codecursor)
7. [Receita 5 — Debug "AI não rodou"](#receita-5--debug-ai-não-rodou)
8. [Receita 6 — Dashboard UI](#receita-6--dashboard-ui)
9. [LLM providers (litellm)](#3-llm-providers-litellm)
10. [Skills, agents, commands](#4-skills-agents-commands)

---

## 1. Setup inicial (5 min)

```bash
git clone <repo> cai && cd cai
cp .env.example .env

# Edita .env: 4 linhas obrigatórias
sed -i.bak "s/APP_TOKEN=.*/APP_TOKEN=$(openssl rand -base64 16)/" .env
sed -i.bak "s/ZAP_API_KEY=.*/ZAP_API_KEY=$(openssl rand -hex 16)/" .env
sed -i.bak "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -base64 12)/" .env
# (Se for usar Anthropic Cloud, adicionar ANTHROPIC_API_KEY=sk-ant-... no .env)

make build       # build da imagem orchestrator (~1min)
make up          # sobe stack
make migrate     # cria schema (Postgres)

# Verifica
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl -sf http://127.0.0.1:8080/health/full -H "X-API-Token: $TOKEN" | jq

# Dashboard
echo "http://127.0.0.1:8080/ui/?token=$TOKEN"
```

---

## 2. 3 modos de invocação

| Modo | Quando usar | Exemplo |
|---|---|---|
| **CLI** | Teste ad-hoc, debug, scan sem AI | `make scan TARGET=http://juice-shop:3000` |
| **REST API** | Integração CI/CD, scan agendado | `POST /scans` (com `X-API-Token`) |
| **Claude Code** | Operação interativa, troubleshooting | Skills auto-invocáveis ou `/comando` |
| **Dashboard UI** | Visibilidade em tempo real | `http://127.0.0.1:8080/ui/` |

---

## Receita 1 — Scan local com LM Studio (do zero ao bundle)

**Objetivo**: scan de aplicação web com triage AI rodando 100% local (dados não saem).

### Pré-requisitos

1. **Instalar LM Studio** (Windows/macOS/Linux): <https://lmstudio.ai/>
2. **Carregar modelo**: na UI do LM Studio → Search → `qwen3.6` ou `qwen2.5-coder` → Download (escolher quantização q4_K_M, ~18GB para 27B em VRAM ≥24GB)
3. **Habilitar Local Server**: aba Developer → Status: Running → porta 1234

### Configurar `.env`

```bash
LLM_MODEL=openai/qwen/qwen3.6-27b
LLM_API_BASE=http://host.docker.internal:1234/v1
LLM_API_KEY=lm-studio
LLM_FALLBACK_MODEL=anthropic/claude-haiku-4-5-20251001  # opcional, p/ fallback cloud
ANTHROPIC_API_KEY=sk-ant-...   # só se quiser fallback
```

### Disparar

```bash
make up
make migrate
make scan TARGET=http://juice-shop:3000
```

Ver no dashboard (aba **AI Calls**): cada batch de triagem aparece como linha com `model=openai/qwen/qwen3.6-27b`, latência, tokens. Se latência muito alta (>30s/batch), aumentar `num_ctx` no LM Studio.

### Output esperado

- HTML técnico em `reports/scan-<id>.html` com seção "Triagem AI" em cada finding
- Bundle JSON em `reports/scan-<id>/ai-bundle.json` com `owasp_top10`, `business_impact`, `suggested_remediation` populados

---

## Receita 2 — Scan REST API com triage AI

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
BASE=http://127.0.0.1:8080

# 1. Cria target
TARGET_ID=$(curl -s -X POST $BASE/targets \
  -H "X-API-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "asset_type": "url",
    "value": "http://juice-shop:3000",
    "criticality": "medium",
    "contains_pii": false
  }' | jq -r '.id')

# 2. Enfileira scan (worker arq processa)
SCAN_ID=$(curl -s -X POST $BASE/scans \
  -H "X-API-Token: $TOKEN" -H "Content-Type: application/json" \
  -d "{\"target_id\":\"$TARGET_ID\",\"scanners\":[\"nmap\",\"zap\"],\"profile\":\"web\"}" \
  | jq -r '.id')

echo "Scan ID: $SCAN_ID"
echo "Cockpit: http://127.0.0.1:8080/ui/cockpit.html?scan_id=$SCAN_ID&token=$TOKEN"

# 3. Acompanhar
watch -n 3 "curl -s $BASE/scans/$SCAN_ID -H 'X-API-Token: $TOKEN' | jq '{state, current_phase, phase_progress}'"

# 4. Quando state=done, baixar bundle
curl -s "$BASE/reports/$SCAN_ID/ai-bundle" -H "X-API-Token: $TOKEN" -o ai-bundle.json
```

---

## Receita 3 — OSINT em domínio público

OSINT é read-only sobre dados públicos — não toca o servidor alvo. Útil pra validar exposure (vazamento de código, secrets em repos públicos, typosquats, presença em Shodan).

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)

# Configurar tokens externos no .env (opcional, mas recomendado)
# GITHUB_TOKEN=ghp_...
# SHODAN_API_KEY=...

curl -X POST http://127.0.0.1:8080/exposure/scan \
  -H "X-API-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "company_name": "Banco Exemplo",
    "domains": ["bancoexemplo.com.br"],
    "github_orgs": ["bancoexemplo"],
    "dorks": ["bancoexemplo password", "bancoexemplo api_key"]
  }'
```

Ver `reports/exposure-*.html`. Findings típicos: subdomínios CT-logged, repos com matches de dorks, secrets verificados via TruffleHog, typosquats com MX ativo.

---

## Receita 4 — Handoff bundle pra Claude Code/Cursor

**Objetivo**: pegar bundle JSON de um scan e mandar pra outra IA propor patches.

```bash
SCAN_ID=<uuid>
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)

# Baixa bundle + gera HANDOFF.md
mkdir -p out/$SCAN_ID
curl -s "http://127.0.0.1:8080/reports/$SCAN_ID/ai-bundle" \
  -H "X-API-Token: $TOKEN" -o out/$SCAN_ID/ai-bundle.json

# Top 5 vulnerabilidades em handoff legível
jq -r '
  .vulnerabilities[:5] | .[] |
  "## [" + .severity + "] " + .title + "\n" +
  "- OWASP: " + (.classification.owasp_top10_2021 // "n/a") + "\n" +
  "- CWE: " + ((.classification.cwe // []) | join(", ")) + "\n" +
  "- Local: " + (.instances[0].location | tostring) + "\n" +
  "- Fix: " + (.remediation.summary // "(sem texto)") + "\n"
' out/$SCAN_ID/ai-bundle.json > out/$SCAN_ID/HANDOFF.md
```

No Claude Code (ou outra IA patcher):
```
Eu te entreguei um AI Fix Bundle em ./ai-bundle.json (schema 1.0.0).

Por favor:
1. Leia o JSON e ordene as vulnerabilidades por patch_priority (1=urgente).
2. Para cada uma, use os code_search_patterns da remediation pra localizar o código vulnerável no repo.
3. Proponha um patch seguindo before_after_examples (formato git diff).
4. Não aplique automaticamente — abra um PR por vulnerability separadamente.
5. No fim, retorne: lista de patches propostos, arquivos tocados, e quais não conseguiu localizar.

Comece pelas críticas. Verificação fica por minha conta — depois eu rodo o scan de novo seguindo verification.rerun.
```

Pelo Claude Code interno do projeto, basta dizer: `"gera handoff do scan X pra Cursor"` — a skill `cai-handoff-fix` cuida.

---

## Receita 5 — Debug "AI não rodou"

Sintoma: você esperava ver triage AI nos findings, mas eles vieram sem `ai_triage`.

```bash
# Pelo Claude Code
"debug LLM"   # invoca skill cai-llm-debug

# Manualmente
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)

# 1. Configuração ativa
grep -E '^(LLM_MODEL|LLM_API_BASE|LLM_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY)=' .env \
  | sed -E 's/(API_KEY=).+/\1<set>/'

# 2. Health
curl -sf "http://127.0.0.1:8080/health/full" -H "X-API-Token: $TOKEN" | jq '.components[] | select(.name | startswith("llm"))'

# 3. Últimas chamadas
docker exec cai-postgres psql -U cai -d cai -c "
SELECT created_at, purpose, model, latency_ms, success, COALESCE(error,'') AS err
FROM ai_runs ORDER BY created_at DESC LIMIT 20;"

# 4. Stats
curl -sf "http://127.0.0.1:8080/ui/api/ai-runs/stats" -H "X-API-Token: $TOKEN" | jq
```

Causas comuns (no [skill cai-llm-debug](.claude/skills/cai-llm-debug/SKILL.md)):
- `--skip-ai` foi usado
- `LLM_API_BASE` vazio mas usuário esperava LM Studio
- LM Studio carregou modelo diferente de `LLM_MODEL`
- Container não alcança `host.docker.internal` (Linux puro precisa `extra_hosts`)
- Fallback automático silencioso pra cloud

---

## Receita 6 — Dashboard UI

```bash
# Pelo Claude Code
/dashboard

# Manualmente
make up
make migrate
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
echo "http://127.0.0.1:8080/ui/?token=$TOKEN"
```

**4 abas**:

- **◉ Dashboard** — health (Postgres/Redis/ZAP/LM Studio/cloud), AI stats (latency p50/p95, fallback rate), charts (modelos usados, severity por scan)
- **⚡ Scans** — todos os scans com fase atual + link pro **cockpit live** de cada um
- **✦ AI Calls** — telemetria de cada chamada LLM (purpose, model, latência, tokens, fallback flag)
- **⌗ Logs** — stream SSE de eventos JSON em tempo real (filtrável)

**Cockpit** (`/ui/cockpit.html?scan_id=X`):
- Timeline visual de fases (queued → nmap → zap → dedup → triage → persist → report → done)
- Findings ao vivo (poll 3s)
- AI calls deste scan
- Logs SSE filtrados pelo scan
- Botão de download do AI Fix Bundle

---

## 3. LLM providers (litellm)

Gateway único em `orchestrator/ai/gateway.py`. **Não importar Anthropic/OpenAI/Ollama SDK direto**.

### 4 cenários de configuração

| Cenário | LLM_MODEL | LLM_API_BASE | LLM_API_KEY | API key adicional |
|---|---|---|---|---|
| **A — Anthropic Cloud** | `anthropic/claude-opus-4-7` | (vazio) | (vazio) | `ANTHROPIC_API_KEY` |
| **B — LM Studio (local)** | `openai/qwen/qwen3.6-27b` | `http://host.docker.internal:1234/v1` | `lm-studio` | (opcional fallback Anthropic) |
| **C — Ollama (em container)** | `ollama/qwen2.5:32b-instruct-q4_K_M` | `http://ollama:11434/v1` | `ollama` | — |
| **D — OpenAI Cloud** | `openai/gpt-4o` | (vazio) | (vazio) | `OPENAI_API_KEY` |

### Fallback automático

Se primário falhar (timeout, 5xx, rate limit), gateway tenta `LLM_FALLBACK_MODEL` automaticamente. Útil pra rodar local + ter cloud como rede de segurança.

### Ver atividade

- Dashboard UI → aba **AI Calls** (todas) ou **Dashboard** (stats agregadas)
- DB direto: `SELECT * FROM ai_runs ORDER BY created_at DESC LIMIT 20`
- Skill `cai-llm-debug` empacota tudo num diagnóstico

### Quirks conhecidos

- **LM Studio rejeita `response_format=json_object`** — gateway omite quando `LLM_API_BASE` setado, parsing de fallback no `complete_json` extrai JSON via regex
- **Modelos de reasoning (Qwen 3.x, DeepSeek-R1)** consomem `max_tokens` em `<think>...</think>` antes de responder. Aumentar pra 8192+ se output vier vazio
- **Context window LM Studio default 50k** — batch grande de findings estoura. Reduzir `triage_batch(batch_size=15)` ou aumentar context window no LM Studio

---

## 4. Skills, agents, commands

### Skills auto-invocáveis (10)

| Skill | Trigger natural |
|---|---|
| `cai-scan` | "rode scan em http://...", "pentest no host X" |
| `cai-exposure` | "tem código vazado?", "scan OSINT", "typosquats" |
| `cai-triage` | "analisa findings do scan X", "monta resumo executivo" |
| `cai-investigate` | "investiga esse finding", "valida exploitability" |
| `cai-handoff-fix` | "gera bundle pra Claude Code", "exporta findings pro Cursor" |
| `cai-add-adapter` | "criar adapter pra ferramenta X" |
| `cai-stack-status` | "está tudo no ar?", "diagnóstico" |
| `cai-self-heal` | "isso quebrou", "scan falhou", "investiga esse bug" |
| `cai-llm-debug` | "testa o LLM", "qual modelo tá sendo usado?" |
| `cai-deploy` | só explícito (`disable-model-invocation: true`) |

### Slash commands (13)

`/up`, `/down`, `/build`, `/migrate`, `/test`, `/lint`, `/status`, `/logs`, `/smoke`, `/backup`, `/db-shell`, `/bundle <scan_id>`, `/dashboard`

### Subagents (4)

- `security-auditor` — review com lente OWASP/pentester
- `adapter-author` — escreve novos ScannerAdapters
- `findings-analyst` — análise estatística agregada
- `fix-bundle-author` — enriquece bundles com patterns/exemplos AI

---

## Recursos adicionais

- [README.md](../README.md) — visão geral do projeto
- [docs/architecture.md](architecture.md) — arquitetura, Finding canônico, dedup
- [docs/runbook.md](runbook.md) — operação dia-a-dia
- [docs/threat-model.md](threat-model.md) — modelo de ameaças
- [.claude/](../.claude/) — skills, commands, agents, rules
