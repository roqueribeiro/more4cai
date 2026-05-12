---
description: Convenções de Docker compose, profiles, variáveis de ambiente
paths:
  - "docker/**"
  - "Dockerfile"
  - ".env.example"
  - "Makefile"
---

# Convenções de Docker

## Profiles

Compose modular com profiles:

| Profile | Inclui | Quando subir |
|---|---|---|
| `default` | orchestrator + worker + postgres + redis + ollama | sempre |
| `scanners` | zap + trivy + kali-toolbox | quando rodar scans |
| `lab` | juice-shop + dvwa + webgoat | testes/desenvolvimento |
| `greenbone` | stack Greenbone (~20 containers) | scan rede sob demanda |
| `obs` | phoenix tracing | debug AI |
| `ai-agent` | cai-expert | Fase 4 agentic |
| `proxy` | caddy TLS | Fase 6 hardening |

Sempre prefixar comando com `--env-file .env` quando rodar `docker compose -f docker/...` — caso contrário `.env` da raiz não é lido.

## Network

- `cai-net` (bridge) é a rede compartilhada — todo container roda nela
- Portas SEMPRE em `127.0.0.1:<host_port>:<container_port>`. **Nunca expor em `0.0.0.0`** sem motivo justificado (compliance bancário)
- `extra_hosts: ["host.docker.internal:host-gateway"]` no orchestrator pra falar com LM Studio no host Windows

## Volumes

Nomeados, persistentes:
- `pgdata` — Postgres
- `ollama_models` — modelos LLM baixados
- `trivy_cache` — DB de vulns Trivy
- `kali_workspace` — workspace efêmero pro Kali toolbox
- `gvm_*` — Greenbone (vários)
- `caddy_data` / `caddy_config` — TLS interno

`./reports`, `./data`, `./config` são bind-mounts.

## Permissões de container

- `cap_add: [NET_RAW, NET_ADMIN]` apenas em `orchestrator` (pro nmap SYN scan funcionar)
- **Nunca usar `--privileged`** sem aprovação
- Containers que NÃO precisam de rede pra fora: não dar `network_mode: host`
- Worker arq compartilha as mesmas caps do orchestrator

## .env

- `.env.example` é template versionado
- `.env` é gitignored — NUNCA commitar
- `pydantic-settings` em `orchestrator/config.py` define o schema
- Adicionar variável nova: atualizar `config.py` + `.env.example` + doc no README

## Imagens

| Imagem | Origem | Tamanho aprox |
|---|---|---|
| `cai-orchestrator:dev` | `docker/images/orchestrator/Dockerfile` | ~500MB |
| `cai-kali-toolbox:dev` | `docker/images/kali-toolbox/Dockerfile` | ~3GB (downloads) |
| `cai-expert:dev` | `docker/images/cai-expert/Dockerfile` | ~1GB |
| `zaproxy/zap-stable` | upstream | ~700MB |
| `aquasec/trivy` | upstream | ~150MB |
| `bkimminich/juice-shop` | upstream | ~250MB |

Build de tudo pode demorar 15-30min na primeira vez. `make build` builda só o orchestrator (rápido).

## Healthcheck

Faltando em vários serviços (TODO). Adicionar `healthcheck:` no compose conforme:
- ZAP: `curl -f http://localhost:8090/JSON/core/view/version/?apikey=$ZAP_API_KEY`
- Postgres: `pg_isready -U cai`
- Redis: `redis-cli ping`
- Orchestrator: `curl -f http://localhost:8080/health`

## Não fazer

- Não rodar `docker compose down -v` em produção (apaga volumes = apaga DB)
- Não modificar `compose.greenbone.yml` ad-hoc — reflita mudanças no upstream Greenbone
- Não adicionar `:latest` em imagens críticas em produção — pin de versão
