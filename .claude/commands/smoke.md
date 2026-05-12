---
description: E2E smoke test — sobe lab, build orchestrator, dispara scan no Juice Shop, gera HTML
allowed-tools: Bash
argument-hint: ""
---

Roda o smoke test E2E:

```bash
bash scripts/smoke.sh
```

O script:
1. Cria `.env` se não existir (cópia de `.env.example`)
2. Build do orchestrator
3. Sobe stack (orchestrator + workers + scanners + lab)
4. Aguarda ZAP e Juice Shop
5. Dispara scan via CLI (`--skip-ai` por padrão se não houver API key)
6. Lista relatórios em `reports/`

Após terminar, reporte:
- Quantos findings foram gerados
- Severity breakdown
- Caminho do HTML
- Qualquer warning/erro no caminho
