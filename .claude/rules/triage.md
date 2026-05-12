---
description: Convenções da camada AI/triage (gateway litellm, scrubber, dedup, prompts)
paths:
  - "orchestrator/ai/**"
  - "orchestrator/domain/scrubber.py"
  - "orchestrator/domain/dedup.py"
---

# Convenções de AI/Triage

## Gateway único: litellm

**TODA chamada LLM passa por `orchestrator.ai.gateway`**. Não importar `anthropic`, `openai`, `ollama` direto.

Por quê:
- Suporte plugável de providers (Anthropic/OpenAI/Ollama/LM Studio/OpenRouter)
- Prompt caching Anthropic configurado num lugar
- Fallback automático em falha
- LM Studio quirks (ex: `response_format=json_object` rejeitado) tratados centralmente
- Observabilidade futura (Phoenix tracing) acopla aqui

Uso:

```python
from orchestrator.ai.gateway import complete, complete_json

text = await complete(messages, cache_system=True, max_tokens=2048)
data = await complete_json(messages, model="anthropic/claude-opus-4-7")
```

## Prompt caching

System prompts grandes são marcados com `cache_control: {type: ephemeral}` automaticamente quando `cache_system=True`. Dá ~80% economia entre lotes (Anthropic). LM Studio/Ollama ignoram silenciosamente.

Pra caching efetivo:
- System prompt deve ser **estável entre chamadas** (não interpolar dados variáveis dele)
- Dados variáveis vão na mensagem `user`
- System >1024 tokens (Anthropic)

## Scrubber (PII redaction)

`orchestrator.domain.scrubber.scrub()` é chamado **antes de qualquer payload sair pro LLM externo**. Cobre regex de:
- Padrões BR-PII (CPF, CNPJ — úteis pra cliente brasileiro)
- Padrões universais: PAN com Luhn, CVV, email, JWT, AWS keys, telefone BR, header `Authorization: Bearer`

Mudar regex do scrubber: adicionar padrão é seguro; relaxar requer revisão. Não confiar em "esse cliente não tem CPF" — sempre passar pelo scrubber.

Quando criar novo prompt envolvendo evidência:

```python
from orchestrator.domain.scrubber import scrub

evidence_safe = scrub(finding.evidence[0].snippet or "")
prompt = f"Evidência: {evidence_safe}"
```

## AIAnalyzer — schema de saída

`triage_batch()` espera JSON estrito do LLM:

```json
{
  "triages": [
    {
      "finding_id": "<uuid>",
      "adjusted_severity": "info|low|medium|high|critical",
      "rationale": "...",
      "is_likely_false_positive": false,
      "business_impact": "...",
      "suggested_remediation": "...",
      "suggested_poc": "...",
      "owasp_top10": "A03:2021-Injection"
    }
  ]
}
```

Se o LLM devolver formato errado, `triage_batch` loga `ai.triage_parse_failed` e segue (não levanta).

## Frameworks de classificação

Sistema é **agnóstico a framework regulatório**. Triagem usa:
- **OWASP Top 10 (2021)** — categoria primária pra web/API
- **CWE** — taxonomia de fraqueza
- **CVSS v3** — score quando disponível

CVE/GHSA chega via `vuln_id` do scanner — não inventar.

## Dedup

`heuristic_dedup` é determinístico, rápido — sempre rodar primeiro.
`semantic_dedup` usa LLM, é caro — só rodar quando explicitamente pedido.

`Finding.deduped_key` é gerado por `model_validator(mode="after")` em `schemas.py`. Se mudar a fórmula, **invalida `vulnerabilities[].id` no AI Fix Bundle** (uuid5 derivado) — patcher perde tracking.

## Modelos sugeridos

- **Triagem geral / narrativa**: `anthropic/claude-opus-4-7` (cloud) ou `qwen/qwen3.6-27b` via LM Studio (local).
- **Classificação leve em batch**: `anthropic/claude-haiku-4-5-20251001`.
- **Local pra dados sensíveis**: LM Studio com `LLM_API_BASE=http://host.docker.internal:1234/v1`.

`LLM_MODEL` no `.env` é primário; `LLM_FALLBACK_MODEL` é fallback automático se primário falhar (sempre cloud).

## LM Studio caveats

- Não aceita `response_format: {type: json_object}` — apenas `json_schema` ou `text`. Gateway omite quando `LLM_API_BASE` está setado.
- Context window default 50k; reduzir batch via `triage_batch(batch_size=N)` se estourar.
- Modelos de reasoning (Qwen 3.x, DeepSeek-R1) consomem `max_tokens` em `<think>...</think>` antes de responder. Aumentar `max_tokens` se output vier vazio.

## Não fazer

- **Não usar OpenAI/Anthropic SDK direto** — passar tudo por litellm que normaliza
- **Não imprimir prompt completo em log de produção** — pode vazar dados
- **Não fazer "AI triage" mexendo direto em `Finding.severity`** — usar `Finding.ai_triage.adjusted_severity` pra preservar a severity original do scanner
