---
name: cai-investigate
description: Investigação profunda de um finding específico via CAI agentic / fallback Claude. Use quando usuário pede "investiga esse finding", "valida se é exploitable", "monta PoC", "esse achado é falso positivo?". Roda sob HITL (dry_run=true por padrão).
when_to_use: investigação aprofundada de finding individual, validação manual, geração de PoC, confirmação de exploitability
argument-hint: "<finding-id-uuid> [--dry-run=true] [--max-steps=10]"
allowed-tools: Bash Read
---

# Skill: Investigação agentic de finding

Diferente do triage em batch (`cai-triage`), este skill aprofunda em **um finding específico** — útil pra validar exploitability, gerar PoC e enriquecer contexto.

## Modo de operação

**SEMPRE `dry_run=true` por padrão**. Mesmo em pentest comercial, executar comandos sob investigação automática num cliente é risco — pode acidentalmente sair do escopo. O agente:

1. Analisa o finding e correlaciona com evidência existente
2. Sugere comandos de validação (curl, dig, openssl) — **não executa**
3. Gera PoC textual (Burp request, payload sqlmap)
4. Avalia probabilidade de FP

Se o usuário **explicitamente** pedir `dry_run=false`, então o agente pode executar comandos da allowlist read-only no `kali-toolbox` (curl, dig, host, nslookup, whois, openssl, ping). Isso ainda é seguro — não muda estado.

## Pré-requisitos

1. Finding existe no DB
2. Orchestrator no ar
3. `ANTHROPIC_API_KEY` (ou OpenAI) no `.env` — fallback Claude

CAI framework instalado é opcional (Fase 4). Sem ele, fallback Claude direto via gateway funciona.

## 1. Identificar finding

```bash
FINDING_ID=$(...)

docker exec cai-postgres psql -U cai -d cai -c \
  "SELECT id, severity, title, source_tool, vuln_id FROM findings WHERE id='$FINDING_ID';"
```

## 2. Disparar investigação

```bash
TOKEN=$(grep APP_TOKEN .env | cut -d= -f2)
curl -X POST http://127.0.0.1:8080/investigate/$FINDING_ID \
  -H "X-API-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"dry_run": true, "max_steps": 10}'
```

## 3. Interpretar saída

Resposta JSON:

```json
{
  "finding_id": "...",
  "transcript": [{"role":"assistant","content":"..."}],
  "final_assessment": "...",
  "dry_run": true,
  "trace_url": null
}
```

`final_assessment` traz:
- **plan** — passos sugeridos
- **evidence_correlation** — o que sustenta vs o que falta
- **risk_assessment** — impacto técnico/operacional
- **false_positive_likelihood** — 0.0-1.0
- **next_actions** — passos seguros pro operador

## 4. Apresentar ao usuário

Resumo focado:

- Verdict: **explorável | provável FP | indeterminado**
- Justificativa em 2-3 linhas
- Evidência adicional necessária
- PoC sugerida (se gerada) — formatar como bloco de código
- Próxima ação recomendada

## 5. (Opcional) Validar com comandos

Se usuário concordar e pedir `dry_run=false`:

```bash
curl -X POST http://127.0.0.1:8080/investigate/$FINDING_ID \
  -H "X-API-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"dry_run": false, "max_steps": 5}'
```

O agente vai rodar comandos read-only no kali-toolbox e enriquecer o assessment.

## Regras de segurança

- **Nunca** executar comando que modifique estado (`DELETE`, `UPDATE`, `rm`, `kill`)
- **Nunca** executar exploit automatizado mesmo se o agente sugerir
- **Sempre** mostrar o comando ANTES de rodar — pra revisão humana
- Se usuário pedir pra "executar tudo automaticamente", recusar — HITL é obrigatório
- **Nunca** investigar findings em alvos fora do escopo do engagement

## Trace observability (opcional)

Se Phoenix está rodando (profile `obs`):

```bash
make obs-up
# ver traces em http://127.0.0.1:6006
```

`trace_url` na resposta vai linkar pra trilha do agente.

## Quando NÃO usar este skill

- Análise em batch de muitos findings → use `cai-triage`
- Scan novo → use `cai-scan`
- Reproduzir o scan original → use o adapter direto via API

## Limitação atual

Integração total com `cai-framework` é stub na Fase 4. O fallback Claude direto funciona pra raciocínio textual, mas não tem tool use ativo no kali. Para investigação que precise rodar comandos de fato, instalar `pip install cai-framework[full]` e configurar — TODO.
