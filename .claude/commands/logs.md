---
description: Mostra os últimos logs do orchestrator (ou de um container específico)
allowed-tools: Bash
argument-hint: "[container-name]"
---

Mostre logs recentes. Se `$ARGUMENTS` vazio, default = `orchestrator`.

```bash
CONTAINER="${1:-orchestrator}"

# se for serviço do compose
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml -f docker/compose.lab.yml logs --tail 100 $CONTAINER

# alternativamente direto
# docker logs cai-$CONTAINER --tail 100
```

Containers disponíveis: `orchestrator`, `worker`, `postgres`, `redis`, `zap`, `juice-shop`, `dvwa`, `webgoat`, `ollama`, `kali-toolbox`.

Se `$ARGUMENTS` for `--all`, mostre todos os serviços ativos.

Sumarize qualquer ERROR ou WARN aparente nos logs e sugira próximo passo.
