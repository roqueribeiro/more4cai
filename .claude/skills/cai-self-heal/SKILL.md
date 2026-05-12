---
name: cai-self-heal
description: Diagnostica falhas no CAI (scans falhados, LLM caiu, ZAP travou, schema desatualizado, container down, bundle inconsistente) e propõe fix concreto com código copiável. Use quando usuário diz "isso quebrou", "tá dando erro", "scan falhou", "investiga esse bug", "AI não rodou", "bundle ficou ruim", "ZAP não responde".
when_to_use: troubleshooting profundo, scan FAILED, AI triage retornou vazio, container caiu, bundle inconsistente, output inesperado
argument-hint: "[scan_id ou área: scan/llm/zap/db]"
allowed-tools: Bash Read Grep
---

# Skill: Self-heal — diagnose + propor fix

Você é o "primeiro responder" do CAI. Quando algo quebra, esta skill investiga sistematicamente e devolve **diagnóstico + fix sugerido com código copiável**. Não aplica patches automaticamente — propõe pra operador aplicar.

## Sequência (em ordem)

### 1. Status containers

```bash
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml -f docker/compose.lab.yml ps
```

Capture quem está `Up`, `Exited`, `unhealthy`, `Restarting`. Casos óbvios:
- Postgres `Exited` → erro `connection refused` em qualquer scan
- ZAP `Restarting` → ZAP_API_KEY incompatível ou volume corrompido
- Worker arq `Exited` → sintoma comum de migration desatualizada

### 2. Scans recentes com falha

```bash
docker exec cai-postgres psql -U cai -d cai -c "
SELECT id, current_phase, state, errors, finished_at - started_at AS elapsed
FROM scans
WHERE state IN ('failed', 'running')
ORDER BY created_at DESC LIMIT 10;
"
```

Olhe o `errors[]` array — strings como:
- `"ai_triage: ..."` → erro na triagem AI
- `"zap: ..."` → bug do ZAP (incl. scan_id=0 pós newSession)
- `"persist: ..."` → DB connection ou schema
- `"adapter.invalid_handle"` → adapter não retornou ScanHandle válido

`current_phase` quando `state=running` mas há tempo de espera longa indica fase específica travada (ex: `zap_passive` por horas = ZAP indexando muito).

### 3. AI runs com falha

```bash
docker exec cai-postgres psql -U cai -d cai -c "
SELECT model, purpose, error, count(*) AS occurrences
FROM ai_runs
WHERE NOT success
GROUP BY model, purpose, error
ORDER BY occurrences DESC LIMIT 10;
"
```

Se `count(*) FROM ai_runs` é zero E o usuário rodou scans com AI, **o gateway nunca persistiu** — ou (a) `--skip-ai` foi usado, ou (b) DB session falhou silenciosamente em `_persist_ai_run`.

### 4. Logs recentes do orchestrator

```bash
docker logs cai-orchestrator --tail 200 2>&1 | grep -iE '"event":.*"(failed|error|crashed)"'
```

Padrões a procurar:
- `llm.primary_failed` → fallback acionou, ver `error` field
- `ai.triage_batch_failed` → batch específico falhou (context overflow, response_format)
- `zap.spider_id_invalid` → bug pós newSession (já tem retry, mas pode faltar)
- `zap.poll_failed` → ZAP travou meio scan
- `adapter.crashed` → adapter levantou exception não-tratada
- `persist.failed` → DB schema desatualizado (rodar `make migrate`)
- `db.sqlite_init_done` mas usuário esperando Postgres → `DATABASE_URL` aponta pro lugar errado

### 5. Catalog de patterns (regex → fix)

| Sintoma | Causa provável | Fix sugerido |
|---|---|---|
| `scan_id.*invalid.*0.*Bad Request` | ZAP retornou `scan_id="0"` após newSession | `zap_adapter._start_spider_with_retry` já cobre; se persistir, restart ZAP container |
| `context.*overflow.*n_keep` | Batch grande estourou janela LM Studio | Reduzir `triage_batch(batch_size=10)` ou aumentar context window LM Studio |
| `connection refused.*postgres` | Postgres down/iniciando | `docker compose --env-file .env up -d postgres && sleep 5 && make migrate` |
| `OPENAI_API_KEY.*invalid\|401` | Chave Anthropic/OpenAI inválida ou expirada | Trocar `.env`; testar com skill `cai-llm-debug` |
| `response_format.*json_object` | LM Studio rejeitou (não suporta) | Gateway já cobre quando `LLM_API_BASE` setado; conferir `.env` |
| `relation .* does not exist` | Migration nova faltando | `make migrate` |
| `Found orphan containers` | Container antigo sem definição | Adicionar `--remove-orphans` ou ignorar |
| `host\.docker\.internal.*unreachable` | Container não consegue alcançar host (LM Studio) | Verificar `extra_hosts` no compose |
| `cai-zap.*unhealthy` mas API responde | Healthcheck cosmético desconfigurado | Cosmético — ignorar |
| `ai_runs` table vazia + scans rodaram com AI | DB session falhou no `_persist_ai_run` | Conferir que migration 0003 rodou; reiniciar orchestrator |
| LM Studio "não usado" mas configurado | Scan rodou com `--skip-ai` ou `LLM_API_BASE` vazio | Conferir `.env`: `LLM_MODEL` deve começar com `openai/` + `LLM_API_BASE` setado |

### 6. Saúde de dependências em paralelo (rápido)

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl -sf "http://127.0.0.1:8080/health/full" -H "X-API-Token: $TOKEN" | jq
```

`overall: degraded` mostra qual componente está `down`. Latência alta em LM Studio (>5s pra `/v1/models`) sugere modelo grande não totalmente carregado.

## Output esperado

Markdown estruturado:

```markdown
# Diagnóstico CAI

**Sintomas observados**:
- ...

**Causa raiz provável**:
- ...

## Fix sugerido

```bash
# 1. ...
docker compose ... 

# 2. ...
make migrate
```

**Por que funciona**: ...

**Como validar**:
```bash
# Reproduzir o cenário, esperado: ...
```
```

Se houver MÚLTIPLOS bugs concorrentes, listar cada um com a mesma estrutura.

## Não fazer

- **Não aplicar patches automaticamente** (decisão do plano: passive only nesse skill)
- **Não dar fix genérico** ("considere validar input") — sempre apontar arquivo/linha/comando
- **Não inventar erro** — se logs estão limpos e DB está OK, dizer isso e perguntar mais contexto
- **Não esconder problema** — se algo está fora do escopo desta skill (ex: bug em libs externas), reportar honestamente

## Limites

- Esta skill é leitor + sugestor. **Não modifica código**.
- Cobertura é melhor pra falhas operacionais. Para bugs novos no código, usa o agent `security-auditor` ou `adapter-author`.
- Se o orchestrator está totalmente down (Postgres + ZAP + workers tudo morto), começar por `docker compose --env-file .env -f docker/compose.yml ... up -d`.
