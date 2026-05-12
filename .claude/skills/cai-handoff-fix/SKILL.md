---
name: cai-handoff-fix
description: Gera AI Fix Bundle (JSON) de um scan e prepara o handoff pra outra IA patcher (Claude Code, Cursor, Copilot). Use quando usuário pede "gera bundle pra IA corrigir", "exporta findings pro Cursor", "manda isso pra outra IA arrumar", "monta pacote de fix", "prepara handoff".
when_to_use: handoff scan→patcher, exportar findings em formato AI-consumable, fechar loop scan→fix→re-scan
argument-hint: "<scan-id-uuid> [--out=path/to/bundle.json]"
allowed-tools: Bash Read Write
---

# Skill: Handoff de findings pra IA patcher

Pega um scan já executado e produz **3 artefatos** pra entregar a uma IA externa que vai propor patches no código:

1. **`ai-bundle.json`** — JSON estruturado seguindo o schema versionado (`schema_version: 1.0.0`)
2. **`HANDOFF.md`** — sumário legível pra humano com top 5 issues por `patch_priority`
3. **Snippet de prompt pronto** — texto que você cola no Claude Code/Cursor/Copilot pra começar a corrigir

## 1. Identificar scan

Se o usuário deu `scan_id`, use direto. Senão liste e pergunte:

```bash
docker exec cai-postgres psql -U cai -d cai -c \
  "SELECT id, target_id, state, finished_at FROM scans
   WHERE state='done' ORDER BY finished_at DESC LIMIT 5;"
```

## 2. Gerar bundle

Via CLI (preferido — gera no FS local):

```bash
SCAN_ID=$1
docker compose -f docker/compose.yml -f docker/compose.scanners.yml --env-file .env \
  run --rm orchestrator bundle $SCAN_ID
```

Saída esperada:
```
AI Fix Bundle gerado: /app/reports/scan-<id>/ai-bundle.json
  schema=1.0.0  vulns=N  crit=X high=Y med=Z
  patcher_auto=A  review=B
```

Ou via API:

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl http://127.0.0.1:8080/reports/$SCAN_ID/ai-bundle \
  -H "X-API-Token: $TOKEN" -o reports/scan-$SCAN_ID/ai-bundle.json
```

## 3. Gerar `HANDOFF.md`

Top 5 vulns ordenadas por `patch_priority` (1 = urgente). Use `jq` pra extrair:

```bash
BUNDLE=reports/scan-$SCAN_ID/ai-bundle.json

cat > reports/scan-$SCAN_ID/HANDOFF.md <<MD
# Handoff de correções — scan $SCAN_ID

Bundle: \`$BUNDLE\` (schema $(jq -r .schema_version $BUNDLE))

## Top 5 vulnerabilidades pra corrigir primeiro

$(jq -r '
  .vulnerabilities[:5] | .[] |
  "### " + .severity + " — " + .title + "\n" +
  "- **Categoria**: " + .category + "\n" +
  "- **OWASP**: " + (.classification.owasp_top10_2021 // "n/a") + "\n" +
  "- **CWE**: " + ((.classification.cwe // []) | join(", ")) + "\n" +
  "- **Local**: " + (.instances[0].location | tostring) + "\n" +
  "- **Remediação**: " + (.remediation.summary // "(sem texto AI)") + "\n" +
  "- **Verificação**: " + (.verification.rerun.expected_outcome // "rerun scanner") + "\n"
' "$BUNDLE")

## Como aplicar

1. Abra o bundle JSON num agente de código (Claude Code, Cursor, Copilot)
2. Use as instruções em \`appendix.patcher_instructions\`
3. Para cada vulnerability, rode \`code_search_patterns\` no repo, proponha patch seguindo \`before_after_examples\`
4. Verifique com \`verification.rerun\` (rodar scan novamente apenas no escopo)
MD

ls -lh reports/scan-$SCAN_ID/
```

## 4. Snippet pra colar no patcher

Apresentar isto ao usuário (literal, pronto pra colar):

```
Eu te entreguei um AI Fix Bundle em ./ai-bundle.json (schema 1.0.0).

Por favor:
1. Leia o JSON e ordene as vulnerabilidades por patch_priority (1=urgente).
2. Para cada uma, use os code_search_patterns da remediation pra localizar o código vulnerável no repo.
3. Proponha um patch seguindo before_after_examples (formato git diff).
4. Não aplique automaticamente — abra um PR por vulnerability separadamente.
5. No fim, retorne: lista de patches propostos, arquivos tocados, e quais não conseguiu localizar.

Comece pelas críticas. Verificação fica por minha conta — depois eu rodo o scan de novo seguindo verification.rerun.
```

## 5. Reportar

Mostre ao usuário:
- Caminho do `ai-bundle.json` (absoluto)
- Caminho do `HANDOFF.md` (legível)
- Total de vulnerabilities, breakdown por severity
- `patcher_auto` vs `needs_human_review`
- O snippet pronto pra colar

## Casos especiais

- **Scan sem `ai_triage`**: bundle ainda gera, mas `owasp_top10` vai null em todas. Avise o usuário que rodar AI triage primeiro melhora a qualidade do bundle. Sugerir: `make scan` ou re-rodar com `LLM_API_BASE` configurado.
- **Bundle muito grande** (>500 vulns): patcher pode não dar conta de tudo. Sugerir filtrar por `severity` e mandar em batches.
- **Scan ainda rodando** (`state != done`): NÃO gerar bundle. Aguardar fim.

## Quando NÃO usar este skill

- Resumo executivo pra stakeholder humano → use `cai-triage` (gera HTML executivo)
- Investigar 1 finding profundamente → use `cai-investigate`
- Re-scan pra validar fix → use `cai-scan` com `target_url` específico
