---
name: cai-llm-debug
description: Debug e teste de conectividade do gateway litellm. Identifica qual provider (Anthropic/OpenAI/Ollama/LM Studio) está ativo, testa conectividade, lista últimas chamadas, calcula latência. Use quando usuário pede "testa o LLM", "qual modelo tá sendo usado?", "o LM Studio está sendo chamado?", "AI tá funcionando?", "debug LLM".
when_to_use: troubleshooting LLM, validação de configuração, teste de conectividade, verificar fallback rate
argument-hint: "[provider opcional: anthropic/openai/local]"
allowed-tools: Bash Read
---

# Skill: LLM debug

Verifica configuração e conectividade do gateway litellm. Reporta o que está ativo, testa, e lista atividade recente.

## 1. Verificar configuração

```bash
echo "=== Configuração LLM no .env ==="
grep -E '^(LLM_MODEL|LLM_FALLBACK_MODEL|LLM_API_BASE|LLM_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY)=' .env \
  | sed -E 's/(API_KEY=).+/\1<set>/'
```

Identifique qual cenário está ativo:

| Cenário | Indicador |
|---|---|
| **A — Anthropic Cloud** | `LLM_MODEL=anthropic/...` + `ANTHROPIC_API_KEY=<set>` + `LLM_API_BASE` vazio |
| **B — LM Studio** | `LLM_MODEL=openai/...` + `LLM_API_BASE=http://host.docker.internal:1234/v1` + `LLM_API_KEY=lm-studio` |
| **C — Ollama em container** | `LLM_MODEL=ollama/...` + `LLM_API_BASE=http://ollama:11434/v1` |
| **D — OpenAI Cloud** | `LLM_MODEL=openai/...` + `OPENAI_API_KEY=<set>` |

## 2. Health check do LLM

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl -sf "http://127.0.0.1:8080/health/full" -H "X-API-Token: $TOKEN" | jq '.components[] | select(.name | startswith("llm"))'
```

Saída esperada:
- `llm_local`: `status=ok` se LM Studio/Ollama configurado e reachable; `disabled` se vazio
- `llm_cloud`: `status=ok` se ANTHROPIC_API_KEY ou OPENAI_API_KEY presente

## 3. Teste E2E mínimo

```bash
docker compose --env-file .env -f docker/compose.yml run --rm --entrypoint python orchestrator -c "
import asyncio
from orchestrator.ai.gateway import complete

async def main():
    msg = [{'role': 'user', 'content': 'Diga apenas: pong'}]
    r = await complete(msg, max_tokens=64, purpose='debug', cache_system=False)
    print('Response:', r)

asyncio.run(main())
"
```

Em caso de falha, observar:
- `litellm.exceptions.APIConnectionError` → endpoint inalcançável
- `litellm.exceptions.AuthenticationError` → key inválida
- `litellm.BadRequestError` → modelo errado (ex: pediu `qwen` mas LM Studio carregou outro)

## 4. Últimas chamadas LLM (do DB)

```bash
docker exec cai-postgres psql -U cai -d cai -c "
SELECT created_at, purpose, model, latency_ms,
       prompt_tokens, completion_tokens,
       success, COALESCE(error, '') AS err
FROM ai_runs
ORDER BY created_at DESC
LIMIT 20;
"
```

**Se `count(*) FROM ai_runs` é zero**: gateway nunca foi chamado **ou** `_persist_ai_run` falhou silenciosamente. Pode ser:
- Todos os scans rodaram com `--skip-ai`
- Migration 0003 não foi aplicada (`make migrate`)
- Erro ao gravar no DB (logs do orchestrator vão ter `ai_run.persist_failed`)

## 5. Estatísticas (via UI API)

```bash
curl -sf "http://127.0.0.1:8080/ui/api/ai-runs/stats" -H "X-API-Token: $TOKEN" | jq
```

Saída:
- `total` — count de calls totais nas últimas 1000
- `by_model` — distribuição (qual modelo dominou)
- `latency_p50/p95` — latência mediana/cauda
- `fallback_rate` — quantas vezes primário falhou e caiu pro fallback (>0.05 é amarelo, >0.20 é vermelho)
- `success_rate` — % de calls bem-sucedidas

## 6. Diagnóstico de "LM Studio não usado"

Sintoma comum: usuário pensa que LM Studio está sendo chamado mas não vê tráfego no LM Studio.

Causas possíveis:
1. **`LLM_API_BASE` vazio** → gateway usa cloud direto. Fix: setar `.env`.
2. **Scan rodou com `--skip-ai`** → gateway nunca foi chamado. Fix: rodar sem o flag.
3. **Modelo no `.env` diferente do carregado** → LM Studio retorna 400 ("model not found"), gateway vai pro fallback cloud silenciosamente. Fix: `curl http://127.0.0.1:1234/v1/models` e bater com `LLM_MODEL`.
4. **Container `cai-orchestrator` em rede que não alcança host** → testar `docker exec cai-orchestrator curl http://host.docker.internal:1234/v1/models`. Em Linux puro, precisa `extra_hosts` no compose.
5. **Fallback automático silencioso** — primário (LM Studio) crashou, gateway foi pra Anthropic. Conferir `ai_runs` rows com `purpose='triage.fallback'`.

## Output esperado

Markdown:

```markdown
# Status do LLM

**Cenário ativo**: B (LM Studio)
**Endpoint**: http://host.docker.internal:1234/v1
**Modelo primário**: openai/qwen/qwen3.6-27b
**Fallback**: anthropic/claude-haiku-4-5-20251001
**Health check**: ✅ llm_local OK (200ms), llm_cloud OK

## Atividade últimas 1h
- Total calls: 47
- Latência p50: 18.2s, p95: 24.1s
- Fallback rate: 4.2% (2 calls)
- Success rate: 95.7%

## Top 3 modelos usados
1. openai/qwen/qwen3.6-27b — 42 calls
2. anthropic/claude-haiku-4-5-20251001 — 4 calls (fallback)
3. ...

## Issues detectados (se houver)
- ⚠️ 2 fallbacks por timeout em batches grandes — sugere reduzir batch_size pra 15
- ✅ Tudo mais OK
```

## Não fazer

- Não imprimir API keys ou content de prompts em texto puro
- Não rodar test calls em loop (custa $$)
