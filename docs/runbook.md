# Runbook operacional — CAI Orchestrator

## Setup inicial

### Requisitos

- **Docker Desktop** com WSL2 backend (Windows) ou **Docker Engine** (Linux)
- **GPU NVIDIA** com drivers atualizados (opcional — para LM Studio / Ollama local)
- **API key Anthropic** ou **OpenAI** (recomendado, pelo menos como fallback)

### Primeira subida

```bash
git clone <repo> cai && cd cai
cp .env.example .env

# Gera secrets fortes
sed -i.bak "s/APP_TOKEN=.*/APP_TOKEN=$(openssl rand -base64 16)/" .env
sed -i.bak "s/ZAP_API_KEY=.*/ZAP_API_KEY=$(openssl rand -hex 16)/" .env
sed -i.bak "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -base64 12)/" .env
rm .env.bak

# (Opcional) Adicione ao menos uma chave LLM:
# echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env

make build
make up
make migrate                # cria/atualiza schema (alembic)
```

### Healthcheck

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)

# Liveness simples
curl http://127.0.0.1:8080/health

# Health agregador (Postgres/Redis/ZAP/LLM)
curl -s http://127.0.0.1:8080/health/full -H "X-API-Token: $TOKEN" | jq

# Dashboard UI (browser)
echo "http://127.0.0.1:8080/ui/?token=$TOKEN"
```

---

## Operação dia-a-dia

### Dashboard UI

`http://127.0.0.1:8080/ui/?token=<APP_TOKEN>` — 4 abas (Dashboard, Scans, AI Calls, Logs) + cockpit live por scan. Detalhes em [README §4](../README.md#4-dashboard-ui).

Pelo Claude Code: `/dashboard` ou `"abre o dashboard"`.

### Disparar scan via CLI

```bash
make scan TARGET=http://juice-shop:3000           # com AI triage
make scan-no-ai TARGET=http://juice-shop:3000     # sem AI (rápido, debug)
```

### Disparar scan via API

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)

# 1. Cria target
TARGET_ID=$(curl -s -X POST http://127.0.0.1:8080/targets \
  -H "Content-Type: application/json" -H "X-API-Token: $TOKEN" \
  -d '{"asset_type":"url","value":"http://juice-shop:3000","criticality":"medium"}' \
  | jq -r .id)

# 2. Enfileira scan
SCAN_ID=$(curl -s -X POST http://127.0.0.1:8080/scans \
  -H "Content-Type: application/json" -H "X-API-Token: $TOKEN" \
  -d "{\"target_id\":\"$TARGET_ID\",\"scanners\":[\"nmap\",\"zap\"]}" \
  | jq -r .id)

# 3. Acompanhar pelo cockpit
echo "http://127.0.0.1:8080/ui/cockpit.html?scan_id=$SCAN_ID&token=$TOKEN"

# Ou via polling REST
curl http://127.0.0.1:8080/scans/$SCAN_ID -H "X-API-Token: $TOKEN" | jq

# 4. Quando state=done — relatórios + bundle
curl http://127.0.0.1:8080/reports/$SCAN_ID -H "X-API-Token: $TOKEN" -o report.html
curl http://127.0.0.1:8080/reports/$SCAN_ID/ai-bundle -H "X-API-Token: $TOKEN" -o ai-bundle.json
```

### Scan OSINT (read-only sobre dados públicos)

```bash
curl -X POST http://127.0.0.1:8080/exposure/scan \
  -H "Content-Type: application/json" -H "X-API-Token: $TOKEN" \
  -d '{
    "company_name": "Cliente Exemplo",
    "domains": ["clienteexemplo.com.br"],
    "github_orgs": ["clienteexemplo"],
    "dorks": ["clienteexemplo password", "clienteexemplo api_key"]
  }'
```

### Investigação agentic de finding

```bash
# dry_run=true (default) — só plano, não executa comandos
curl -X POST http://127.0.0.1:8080/investigate/$FINDING_ID \
  -H "Content-Type: application/json" -H "X-API-Token: $TOKEN" \
  -d '{"dry_run": true, "max_steps": 10}'
```

### Gerar AI Fix Bundle (handoff pra IA patcher)

```bash
# CLI
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml \
  run --rm orchestrator bundle $SCAN_ID

# REST
curl http://127.0.0.1:8080/reports/$SCAN_ID/ai-bundle \
  -H "X-API-Token: $TOKEN" -o ai-bundle.json

# Pelo Claude Code
"gera bundle do scan X"     # invoca skill cai-handoff-fix
```

---

## Engagement comercial — antes do scan ativo

CAI removeu gates internos durante a transição banco→pentest comercial. Responsabilidade de autorização é **do operador**:

1. **Escopo escrito do contrato** com o cliente — URLs, IPs, repos públicos autorizados
2. **Janela de execução** combinada com o cliente (especialmente pra ZAP active scan / Nuclei)
3. **Comunicação prévia ao cliente** se algum SOC monitora o alvo (evita falso alarme)
4. **Verificação se host está atrás de CDN** (Cloudflare/Fastly/Akamai) — scan ativo viola ToS do CDN; alternativas: apontar pro IP de origem, ou pedir whitelist da CDN

Ferramentas que **mudam estado** (ZAP active scan, Metasploit) — só rodar com autorização explícita.

---

## Greenbone (opt-in, scan de rede)

```bash
make greenbone-up
# aguarde feed sync (30min-3h, ~5GB)
bash scripts/feed-sync.sh

# Acessar GSA web: https://127.0.0.1:9392 (admin/admin → TROCAR)
# Orchestrator fala via GMP TCP em :9390
```

Configurar `.env`:
```bash
GREENBONE_HOST=greenbone-gmp-tcp
GREENBONE_PORT=9390
GREENBONE_USERNAME=admin
GREENBONE_PASSWORD=<senha-trocada>
```

---

## LM Studio local (opt-in, dados sensíveis)

1. Instalar LM Studio: <https://lmstudio.ai/>
2. Carregar modelo (ex: `qwen3.6-27b` q4_K_M)
3. Aba **Developer** → habilitar Local Server (porta 1234)
4. Editar `.env`:
   ```bash
   LLM_MODEL=openai/qwen/qwen3.6-27b
   LLM_API_BASE=http://host.docker.internal:1234/v1
   LLM_API_KEY=lm-studio
   LLM_FALLBACK_MODEL=anthropic/claude-haiku-4-5-20251001  # opcional
   ```
5. Restart orchestrator: `docker compose -f docker/compose.yml --env-file .env restart orchestrator worker`
6. Validar pelo dashboard: aba Dashboard → cards de health → `llm_local: ok`

---

## Backup

```bash
make backup
# salva em backups/YYYYMMDD-HHMMSS/{cai.sql.gz, reports.tar.gz}
```

Recomendação: cron diário + sync pra storage off-host (S3/Azure Blob).

---

## Atualização de versão

```bash
git pull
make build
make migrate         # aplica novas migrations alembic
make up
```

Rolling update sugerido em prod: worker primeiro (drena fila arq), depois orchestrator.

---

## Troubleshooting

> **Skill `cai-self-heal`** faz diagnóstico automático. Pelo Claude Code:
> ```
> "isso quebrou"        # ou "scan falhou", "AI não rodou", "bundle ficou ruim"
> ```
> Lê `ScanRow.errors`, `ai_runs` com falha, logs JSON, status containers, e propõe fix concreto com código copiável.

### Diagnóstico rápido

```bash
# Pelo Claude Code
/status              # lista containers + endpoints

# Manualmente
make ps              # quem está up/down
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl -s http://127.0.0.1:8080/health/full -H "X-API-Token: $TOKEN" | jq
```

### LLM debug

```
"testa o LLM"        # invoca skill cai-llm-debug
"qual modelo tá sendo usado?"
```

Manualmente:
```bash
# Configuração
grep -E '^(LLM_MODEL|LLM_API_BASE|ANTHROPIC_API_KEY)' .env | sed -E 's/(KEY=).+/\1<set>/'

# Health do LLM
curl -s http://127.0.0.1:8080/health/full -H "X-API-Token: $TOKEN" \
  | jq '.components[] | select(.name | startswith("llm"))'

# Últimas chamadas
docker exec cai-postgres psql -U cai -d cai -c "
  SELECT created_at, purpose, model, latency_ms, success, COALESCE(error,'') AS err
  FROM ai_runs ORDER BY created_at DESC LIMIT 20;"

# Stats agregadas
curl -s http://127.0.0.1:8080/ui/api/ai-runs/stats -H "X-API-Token: $TOKEN" | jq
```

### Bug "LM Studio não está sendo usado"

Causas comuns:
1. **`--skip-ai` foi usado** → roda scan sem o flag
2. **`LLM_API_BASE` vazio** no `.env` → gateway vai pro cloud direto
3. **Modelo no `.env` ≠ modelo carregado no LM Studio** → 400 silencioso, gateway cai pro fallback
4. **Container não alcança host** (Linux puro precisa `extra_hosts` no compose — já está)

### ZAP travou / scan_id=0

Bug histórico (corrigido com retry em `zap_adapter._start_spider_with_retry`). Se persistir:

```bash
docker logs cai-zap --tail 50
# se necessário, reset:
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml restart zap
```

### Postgres `relation does not exist`

Migration nova faltando:
```bash
make migrate
```

Verificar versão atual:
```bash
docker exec cai-postgres psql -U cai -d cai -c "SELECT version_num FROM alembic_version;"
```

### Worker arq não pega jobs

```bash
docker logs cai-worker --tail 100
docker exec cai-redis redis-cli LLEN arq:queue
```

Se a fila tem jobs e o worker não processa: restart worker, verificar logs por erro de import.

### `ai_runs` table vazia mas rodei scans com AI

Causas:
1. Migration 0003 não foi aplicada → `make migrate`
2. Erro silencioso ao gravar no DB → procurar `ai_run.persist_failed` em `docker logs cai-orchestrator`
3. Todos os scans foram com `--skip-ai` → óbvio, conferir histórico

### Greenbone feed travado

```bash
docker logs cai-gvm-feeds -f
# Se travar > 6h:
docker compose --env-file .env -f docker/compose.greenbone.yml --profile greenbone restart
```

### Dashboard UI 401 Unauthorized

Token errado ou faltando:
- URL deve ter `?token=$APP_TOKEN`
- Header `X-API-Token: $APP_TOKEN` se for chamada via curl
- Token persiste em `localStorage` após primeiro acesso na mesma URL

### SSE desconecta a cada 30s

Proxy/firewall corta long-polling. EventSource reconecta automaticamente — cosmético no MVP. Se precisar persistir, usar WebSocket (TODO).

---

## Incident response

### Suspeita de scan tocou alvo fora do escopo

1. **Imediato**: `make down` (mata worker arq + orchestrator)
2. Inspecionar histórico:
   ```sql
   SELECT s.id, s.target_id, t.value, s.started_at, s.state, s.errors
   FROM scans s LEFT JOIN targets t ON t.id = s.target_id
   WHERE s.created_at >= '<timestamp>'
   ORDER BY s.created_at;
   ```
3. Identificar quais scans rodaram, contra quais alvos
4. Comunicar cliente do engagement com transparência

### Vazamento detectado em finding (PII/credencial)

1. Não rodar mais scans no ativo até cliente decidir
2. Comunicar cliente do engagement (eles é que decidem se há obrigação de notificação regulatória)
3. Bundle e relatório HTML já passam por `scrubber.scrub()` — credenciais nos snippets são redacionadas

---

## Skills, commands, agents (Claude Code)

Listagem completa em [README §8](../README.md#8-self-heal-e-debug). Mais usados no dia-a-dia:

- `/dashboard` — abre UI
- `/status` — diagnóstico stack
- `/up` / `/down` / `/migrate` / `/test` / `/lint`
- `/bundle <scan_id>` — gera AI Fix Bundle
- `"isso quebrou"` → `cai-self-heal`
- `"testa o LLM"` → `cai-llm-debug`

---

## Referências

- [README.md](../README.md) — overview + quickstart
- [docs/usage.md](usage.md) — cookbook (6 receitas)
- [docs/architecture.md](architecture.md) — arquitetura detalhada
- [docs/threat-model.md](threat-model.md) — atores, dados sensíveis
