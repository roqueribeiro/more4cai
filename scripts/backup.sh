#!/usr/bin/env bash
# Backup do Postgres + reports.
# Para retenção real, agendar via cron e enviar pra storage off-host.

set -euo pipefail

cd "$(dirname "$0")/.."

TS=$(date +%Y%m%d-%H%M%S)
OUT_DIR="backups/${TS}"
mkdir -p "$OUT_DIR"

echo "==> [1/2] Postgres dump"
docker exec cai-postgres pg_dump -U cai cai | gzip > "${OUT_DIR}/cai.sql.gz"

echo "==> [2/2] Reports tarball"
tar czf "${OUT_DIR}/reports.tar.gz" reports/

echo "==> Backup completo em: $OUT_DIR"
ls -lh "$OUT_DIR"
