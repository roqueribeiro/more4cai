---
description: Roda ruff + mypy no código do orchestrator
allowed-tools: Bash
argument-hint: ""
---

Lint + type check:

```bash
docker compose --env-file .env -f docker/compose.yml run --rm --entrypoint sh orchestrator -c \
  "ruff check orchestrator && ruff format --check orchestrator && mypy orchestrator"
```

Para auto-fix:

```bash
docker compose --env-file .env -f docker/compose.yml run --rm --entrypoint sh orchestrator -c \
  "ruff format orchestrator && ruff check --fix orchestrator"
```

Reporte número de erros/warnings por categoria.
