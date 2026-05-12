---
description: Sobe stack se preciso e abre o dashboard UI no navegador (URL + token)
allowed-tools: Bash
argument-hint: ""
---

```bash
# Se stack não está no ar, sobe
if ! docker ps --format '{{.Names}}' | grep -q '^cai-orchestrator$'; then
  echo "Subindo stack..."
  make up
  sleep 5
  make migrate
fi

# Pega token
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)

echo ""
echo "🌐 Dashboard CAI"
echo "   URL: http://127.0.0.1:8080/ui/?token=${TOKEN}"
echo ""
echo "Abas disponíveis:"
echo "  ◉ Dashboard — visão geral, health, charts"
echo "  ⚡ Scans — pentests executados (link pra cockpit em cada um)"
echo "  ✦ AI Calls — telemetria de cada chamada LLM (model, latência, tokens, fallback)"
echo "  ⌗ Logs — stream SSE de eventos do orchestrator"
echo ""
echo "Cockpit live de scan: http://127.0.0.1:8080/ui/cockpit.html?scan_id=<id>&token=${TOKEN}"
```

Reportar a URL pro usuário copiar/colar no navegador. Se possível, mencionar que `?token=...` está embutido (sessão persistida no localStorage após primeira visita).
