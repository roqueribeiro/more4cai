---
description: Roda pytest (todos os testes ou alvo específico)
allowed-tools: Bash
argument-hint: "[caminho/teste/opcional.py]"
---

Roda os testes unitários. Se `$ARGUMENTS` for vazio, roda todos. Senão, roda só o alvo.

```bash
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml run --rm --entrypoint pytest orchestrator -q $ARGUMENTS
```

Para rodar com cobertura:
```bash
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml run --rm --entrypoint pytest orchestrator --cov=orchestrator --cov-report=term-missing
```

Reporte: total de testes, falhas, % de cobertura (se aplicável).
