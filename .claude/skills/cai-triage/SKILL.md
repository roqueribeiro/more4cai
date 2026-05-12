---
name: cai-triage
description: Analisa findings de um scan já executado, prioriza por OWASP/CWE/CVSS, gera narrativa executiva. Use quando usuário pede "analisa os findings do scan X", "quais são os críticos?", "o que é falso positivo?", "monta um resumo executivo".
when_to_use: análise pós-scan, triagem AI, priorização técnica, geração de narrativa executiva
argument-hint: "<scan-id-uuid> [--executive] [--export-defectdojo] [--bundle]"
allowed-tools: Bash Read
---

# Skill: Triagem de findings

Use depois de um scan completar. Pode ser que o scan já tenha rodado AI triage (`triage_batch` no pipeline) — se sim, este skill é pra **gerar relatório executivo**, **explorar findings específicos** ou **gerar AI Fix Bundle pra patcher externo**.

## 1. Identificar o scan

Se o usuário deu `scan_id`, use direto. Se não:

```bash
# último scan no DB
docker exec cai-postgres psql -U cai -d cai -c \
  "SELECT id, target_id, state, finished_at FROM scans ORDER BY created_at DESC LIMIT 5;"
```

Confirme com o usuário qual é o relevante.

## 2. Resumo do scan

```bash
SCAN_ID=$(...)

# stats
docker exec cai-postgres psql -U cai -d cai -c \
  "SELECT severity, count(*) FROM findings WHERE scan_id='$SCAN_ID' GROUP BY severity ORDER BY count DESC;"

# top findings
docker exec cai-postgres psql -U cai -d cai -c \
  "SELECT severity, source_tool, title, vuln_id FROM findings
   WHERE scan_id='$SCAN_ID' ORDER BY severity LIMIT 20;"
```

## 3. Análise

Foque em:

### Críticos/altos
- Quantos? Quais ferramentas detectaram?
- Há **CVEs com CVSS≥9.0**? São exploráveis remotamente?
- Categoria OWASP dominante? (A03 Injection, A01 BAC etc.)

### Falsos positivos prováveis
Findings com `confidence=tentative` + `is_likely_false_positive=true` (campo de `ai_triage`):

```bash
docker exec cai-postgres psql -U cai -d cai -c \
  "SELECT title, payload->'ai_triage'->>'rationale'
   FROM findings WHERE scan_id='$SCAN_ID'
   AND payload->'ai_triage'->>'is_likely_false_positive' = 'true' LIMIT 10;"
```

### Distribuição por OWASP

```bash
docker exec cai-postgres psql -U cai -d cai -c \
  "SELECT payload->'ai_triage'->>'owasp_top10' AS owasp, count(*)
   FROM findings WHERE scan_id='$SCAN_ID'
   GROUP BY owasp ORDER BY count DESC;"
```

## 4. Reporting

Se usuário quer relatório executivo (HTML):

```bash
TOKEN=$(grep APP_TOKEN .env | cut -d= -f2)
curl http://127.0.0.1:8080/reports/$SCAN_ID -H "X-API-Token: $TOKEN" -o report.html
```

## 5. AI Fix Bundle (handoff pra patcher)

Se o usuário quer entregar pra outra IA corrigir o código:

```bash
# Via API
curl http://127.0.0.1:8080/reports/$SCAN_ID/ai-bundle -H "X-API-Token: $TOKEN" -o ai-bundle.json

# Via CLI
docker compose --env-file .env -f docker/compose.yml run --rm orchestrator bundle $SCAN_ID
```

Use o skill `cai-handoff-fix` pra empacotar com `HANDOFF.md` legível pra Claude Code/Cursor.

## 6. Export DefectDojo (opcional)

Se DefectDojo configurado em `.env`:

```bash
curl -X POST http://127.0.0.1:8080/reports/$SCAN_ID/export/defectdojo \
  -H "X-API-Token: $TOKEN"
```

## 7. Próximos passos sugeridos

Para cada finding `critical`/`high`, sugira:

1. **Owner técnico**: time responsável pelo ativo
2. **SLA de remediação**: discutir com cliente do engagement
3. **Re-scan pós-fix**: novo `POST /scans` referenciando o ticket de correção (campo `actor`)
4. **Bundle handoff**: gerar bundle e mandar pro patcher AI fechar o loop

## Não fazer

- Não inventar CVEs que não estão no Finding
- Não recomendar ações destrutivas sem confirmar com o cliente do engagement
- Não prometer SLA sem checar contrato/escopo
