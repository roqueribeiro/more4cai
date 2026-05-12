#!/usr/bin/env bash
# Acompanha o feed sync inicial do Greenbone (vai demorar 30min-3h).

set -euo pipefail

echo "Aguardando containers Greenbone subirem..."
sleep 5

echo "==> Status dos feeds:"
docker logs cai-gvm-feeds --tail 20 2>/dev/null || echo "(feeds container não rodando)"

echo ""
echo "==> Verificando NVTs carregados (vai aumentar conforme o sync progride):"
docker exec cai-gvmd gvmd --get-config 2>/dev/null | head -20 || true

echo ""
echo "Para acompanhar em tempo real:"
echo "  docker logs cai-gvm-feeds -f"
echo ""
echo "Quando terminar:"
echo "  - GSA web: https://127.0.0.1:9392 (admin/admin)"
echo "  - GMP TCP: 127.0.0.1:9390"
echo "  - Trocar senha admin antes de qualquer scan!"
