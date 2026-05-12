#!/usr/bin/env bash
# Smoke test E2E: sobe lab + scanners + orchestrator e roda scan no Juice Shop.
# Uso: bash scripts/smoke.sh

set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE="docker compose --env-file .env --project-directory . -f docker/compose.yml -f docker/compose.scanners.yml -f docker/compose.lab.yml"
PROFILES="--profile default --profile scanners --profile lab"

echo "==> [1/5] Verificando .env"
if [[ ! -f .env ]]; then
  echo "  .env não existe. Copiando de .env.example..."
  cp .env.example .env
  echo "  EDITE .env com suas API keys antes de continuar (Ctrl-C pra abortar)"
  echo "  Pressione ENTER quando estiver pronto..."
  read -r
fi

echo "==> [2/5] Build das imagens"
$COMPOSE build orchestrator worker kali-toolbox

echo "==> [3/5] Subindo stack"
$COMPOSE $PROFILES up -d

echo "==> [4/5] Aguardando serviços (até 2min)..."
for i in {1..60}; do
  if curl -sf http://127.0.0.1:3000 >/dev/null 2>&1 \
     && curl -sf "http://127.0.0.1:8090/JSON/core/view/version/?apikey=${ZAP_API_KEY:-changeme}" >/dev/null 2>&1 \
     && curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo "  serviços prontos."
    break
  fi
  sleep 2
done

echo "==> [5/5] Disparando scan via CLI (síncrono, gera HTML)"
$COMPOSE run --rm orchestrator scan "http://juice-shop:3000" --asset-type url --criticality medium "$@"

echo ""
echo "==> DONE. Veja o relatório em reports/scan-*.html"
ls -lt reports/ | head -5
