---
description: Backup de Postgres + reports
allowed-tools: Bash
argument-hint: ""
---

Roda o script de backup:

```bash
bash scripts/backup.sh
```

Gera em `backups/YYYYMMDD-HHMMSS/`:
- `cai.sql.gz` — pg_dump do Postgres
- `reports.tar.gz` — todos os relatórios HTML

Em produção: este script seria agendado via cron + sync pra storage off-host (S3/Azure Blob).

Reporte tamanho de cada artefato e caminho final.
