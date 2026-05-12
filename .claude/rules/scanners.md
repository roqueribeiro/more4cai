---
description: Convenções para criar/manter ScannerAdapters em orchestrator/adapters/
paths:
  - "orchestrator/adapters/**"
  - "tests/unit/test_*adapter*"
---

# Convenções de ScannerAdapter

Todo adapter implementa o `ScannerAdapter` Protocol em `orchestrator/adapters/base.py`. **Não criar variantes** — se o lifecycle não bate, o adapter está modelado errado.

## Lifecycle obrigatório

```python
class XyzAdapter:
    name = "xyz"  # ID curto, lowercase, sem espaço

    async def health(self) -> bool: ...
    async def start_scan(self, target: Target, options: dict) -> ScanHandle: ...
    async def poll(self, handle: ScanHandle) -> ScanStatus: ...
    async def fetch_results(self, handle: ScanHandle) -> RawResults: ...
    async def normalize(self, raw: RawResults) -> list[Finding]: ...
```

- `health()` SEMPRE retorna `bool`. Nunca lança. Captura `FileNotFoundError`/`PermissionError` e retorna False.
- `start_scan()` é **não-bloqueante**. Subprocess → guarda task em `self._tasks[native_id]`. Retorna `ScanHandle` imediato.
- `poll()` retorna `RUNNING/DONE/FAILED/CANCELED`. Nunca bloqueia mais de 100ms.
- `fetch_results()` só é chamado quando `poll() == DONE`.
- `normalize()` retorna `list[Finding]` — sempre — mesmo em erro (lista vazia + log).

## Schema de saída — Finding canônico

Todos os adapters produzem `orchestrator.domain.schemas.Finding`. **Não inventar campos**.

Campos obrigatórios:
- `scan_id` — placeholder UUID; pipeline reescreve
- `target` — Pydantic `Target` com `asset_type` e `value`
- `source_tool` — igual a `self.name`
- `title` — uma linha, descritiva
- `description` — pode ser longo; truncar evidências enormes a ~2000 chars
- `severity` — heurística do scanner; AI ajusta depois em `ai_triage.adjusted_severity`

Campos quase-sempre úteis:
- `source_rule_id` — ID nativo do scanner (plugin id ZAP, template id Nuclei, OID Greenbone)
- `vuln_id` — CVE quando houver
- `cwe[]` — lista de CWEs
- `confidence` — `tentative/firm/certain` baseado em quão certeira é a detecção
- `evidence[]` — `Evidence(description=, snippet=, request=, response=, payload=)`
- `remediation` — texto se o scanner fornecer

**Nunca** sobrescrever `severity` com base em contexto do alvo (PII/PCI). Isso é trabalho do `AIAnalyzer`. O scanner só reporta o que viu.

## Subprocess vs HTTP API

- **Binário CLI** (nmap, nuclei, gitleaks, trufflehog, dnstwist, checkov, kube-bench, trivy CLI):
  - Usar `asyncio.create_subprocess_exec` com argv list (não shell)
  - `tempfile.mkdtemp(prefix="cai-<adapter>-")` pra outputs
  - Guardar o `Task` em `self._tasks[native_id]` e o output path em `self._outputs[native_id]`
- **HTTP API** (zap, trivy server, github, shodan):
  - `httpx.AsyncClient` com `base_url` e `timeout`
  - Implementar `aclose()` pra cleanup
  - Não vazar API key em logs

## Testes

Todo adapter novo precisa de:
1. Unit test mockando o backend (sem rede real)
2. Fixture XML/JSON real em `tests/fixtures/<adapter>_sample.xml`
3. Teste de `normalize(raw)` com a fixture validando ≥1 Finding

Padrão de nome: `tests/unit/test_<adapter>_adapter.py`.

## Adicionando ao pipeline

Adapter novo NÃO é automaticamente chamado pelo `run_scan()`. Para integrar:

1. Adicionar instância em `orchestrator/jobs/pipelines.py:run_scan()` ou `pipelines/exposure.py:run_exposure_scan()`
2. Documentar no `README.md` (tabela de adapters)
3. Registrar dependência (binário) no Dockerfile do `kali-toolbox` se for CLI
4. Adicionar permissions no `.claude/settings.json` se o adapter rodar binário novo

## Severity heurística

Quando o scanner não fornece severity nativo (Nmap, kube-bench scored), use:
- Banner/info sem exploração direta → `info` ou `low`
- Serviço inseguro exposto (telnet, ftp, smb) → `high`
- Serviço comum em porta padrão (22, 80, 443) → `info`
- Falha CIS K8s scored → `medium`; not scored → `low`

Sempre justificar a heurística em comentário no código.
