---
name: cai-stack-status
description: Verifica saúde da stack CAI (containers, DB, scanners, AI gateway). Use quando usuário pede "está tudo no ar?", "diagnóstico", "por que isso não funciona?", "verifica stack". Identifica peças paradas e sugere correção.
when_to_use: troubleshooting, healthcheck, diagnóstico antes de scan
argument-hint: ""
allowed-tools: Bash Read
---

# Skill: Diagnóstico da stack

Use quando algo não funciona ou antes de iniciar trabalho. Verifica em ordem:

## 1. Containers up

```bash
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml -f docker/compose.lab.yml ps
```

Esperado pra modo "scan completo":
- `cai-orchestrator` — UP
- `cai-worker` — UP (se modo API)
- `cai-postgres` — UP
- `cai-redis` — UP
- `cai-zap` — UP (mesmo se "unhealthy", checar API)
- `cai-juice-shop` — UP
- `cai-ollama` — UP (se GPU disponível)

Se faltar algo crítico, sugerir `make up`.

## 2. Network

```bash
docker network inspect cai_cai-net | jq '.[0].Containers | keys'
```

Todos os containers conectados? Se algum está fora, rebuild ou recreate.

## 3. ZAP API

```bash
ZAP_KEY=$(grep '^ZAP_API_KEY' .env | cut -d= -f2)
curl -sf "http://127.0.0.1:8090/JSON/core/view/version/?apikey=$ZAP_KEY" | jq
```

Se 401: chave errada — checar `.env`.
Se 5xx ou nada: ZAP ainda subindo ou crashou — `docker logs cai-zap | tail -50`.

## 4. Postgres

```bash
docker exec cai-postgres pg_isready -U cai -d cai
docker exec cai-postgres psql -U cai -d cai -c "\dt"
```

Se `relation does not exist` em scan: `make migrate` não rodou. Sugerir.

## 5. Redis

```bash
docker exec cai-redis redis-cli ping
docker exec cai-redis redis-cli LLEN arq:queue
```

Fila grande? Worker pode estar travado. Reiniciar `cai-worker`.

## 6. Orchestrator API

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl -sf http://127.0.0.1:8080/health | jq
```

Se conexão recusada: orchestrator parado. `docker logs cai-orchestrator | tail -50`.

## 7. AI gateway (litellm)

Verificar `.env`:
- Tem `ANTHROPIC_API_KEY` ou `OPENAI_API_KEY`?
- `LLM_LOCAL_BASE_URL` aponta pra serviço acessível? (Ollama no compose ou LM Studio no host)

```bash
# Se LLM_LOCAL_BASE_URL=http://ollama:11434/v1
docker exec cai-orchestrator curl -sf http://ollama:11434/api/tags | jq '.models[] | .name'

# Se LM Studio no host
curl -sf http://127.0.0.1:1234/v1/models | jq
```

Sem chave externa nem local, sugerir `--skip-ai` em scans.

## 8. Adapters específicos (sob demanda)

### Greenbone (Fase 3)
```bash
docker compose --env-file .env -f docker/compose.greenbone.yml ps
# se rodando, checar feed
docker logs cai-gvm-feeds --tail 20
```

### kali-toolbox (Fase 2.5)
```bash
docker exec cai-kali-toolbox which nuclei gitleaks trufflehog dnstwist trivy
```

## Reporte estruturado

Apresentar como tabela:

```
| Componente   | Status | Observação                       |
|--------------|--------|----------------------------------|
| orchestrator | UP     | API responde                     |
| postgres     | UP     | 5 tabelas, 1 scan persistido    |
| zap          | UP     | (unhealthy mas API OK)          |
| ollama       | DOWN   | sem GPU detectada               |
| ANTHROPIC_API_KEY | OK | configurado                     |
```

Sugestões de remediação no fim, em ordem:
1. Críticas: o que precisa subir agora pra desbloquear o usuário
2. Importantes: o que afeta funcionalidade
3. Cosmético: warnings ignoráveis (ex.: "unhealthy" do ZAP)

## Não fazer

- Não restartar containers automaticamente — confirme com usuário primeiro
- Não acessar logs com `docker logs -f` (sem timeout) — usar `--tail`
