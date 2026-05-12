---
description: Diagnóstico rápido da stack — containers, DB, ZAP, AI gateway
allowed-tools: Bash
argument-hint: ""
---

Verifique saúde da stack em ordem rápida:

```bash
echo "=== Containers ==="
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml -f docker/compose.lab.yml ps

echo ""
echo "=== Orchestrator API ==="
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl -sf http://127.0.0.1:8080/health -H "X-API-Token: $TOKEN" | jq 2>/dev/null || echo "DOWN"

echo ""
echo "=== ZAP API ==="
ZAP_KEY=$(grep '^ZAP_API_KEY' .env | cut -d= -f2)
curl -sf "http://127.0.0.1:8090/JSON/core/view/version/?apikey=$ZAP_KEY" | jq 2>/dev/null || echo "DOWN"

echo ""
echo "=== Juice Shop ==="
curl -sf -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000

echo ""
echo "=== Postgres ==="
docker exec cai-postgres pg_isready -U cai -d cai 2>/dev/null
docker exec cai-postgres psql -U cai -d cai -c "SELECT 'targets' as t, count(*) FROM targets UNION ALL SELECT 'scans', count(*) FROM scans UNION ALL SELECT 'findings', count(*) FROM findings UNION ALL SELECT 'audit_log', count(*) FROM audit_log;" 2>/dev/null

echo ""
echo "=== Redis (arq queue) ==="
docker exec cai-redis redis-cli ping 2>/dev/null
docker exec cai-redis redis-cli LLEN arq:queue 2>/dev/null

echo ""
echo "=== AI keys ==="
grep -E '^ANTHROPIC_API_KEY|^OPENAI_API_KEY|^LLM_LOCAL_BASE_URL|^LLM_MODEL' .env | sed 's/=.*/=<set>/' | sed 's/=<set>$/=(empty)/' 2>/dev/null
```

Sumarize em 5-7 linhas o que está UP, DOWN, o que falta. Sugira próximo passo de remediação se houver problema.
