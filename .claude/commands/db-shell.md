---
description: Abre psql shell no Postgres do CAI (read-write — cuidado)
allowed-tools: Bash
argument-hint: ""
---

Abre psql shell interativo no DB do CAI:

```bash
docker exec -it cai-postgres psql -U cai -d cai
```

**Não usar** este comando pra fazer mudanças em `audit_log` — é append-only por design e tem trigger Postgres bloqueando UPDATE/DELETE.

Para queries read-only rápidas, prefira o slash command `/audit` (audit log) ou consultas pontuais via `docker exec ... psql -c "..."`.

Tabelas disponíveis: `targets`, `scans`, `findings`, `audit_log`, `ai_runs`, `alembic_version`.
