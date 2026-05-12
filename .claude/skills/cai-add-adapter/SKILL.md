---
name: cai-add-adapter
description: Adiciona um novo ScannerAdapter ao projeto. Use quando usuário pede "criar adapter pra X", "integrar a ferramenta Y", "adicionar suporte a Z scanner". Gera código boilerplate seguindo o ScannerAdapter Protocol e atualiza pipeline + Dockerfile + README.
when_to_use: integração de novo scanner, criação de adapter, expansão da plataforma
argument-hint: "<adapter-name> <tool-binary-or-api>"
allowed-tools: Read Edit Write Glob Grep
---

# Skill: Adicionar novo ScannerAdapter

Use este skill quando o usuário quer integrar uma nova ferramenta de scan no CAI. O processo segue ordem rígida — não pular etapas.

## 1. Coletar requisitos

Pergunte ao usuário (em uma única mensagem):

1. **Nome** do adapter (snake_case): `xyz_adapter`
2. **Tipo de integração**: subprocess (CLI) ou HTTP API?
3. **Saída**: JSON, XML, JSONL?
4. **Binário/imagem Docker**: caso CLI, está no kali-toolbox? Senão, qual imagem?
5. **Categoria**: web, rede, OSINT, cloud, k8s? (define qual pipeline integra)

## 2. Estudar adapter existente similar

Antes de escrever, leia o adapter mais próximo:

- **Subprocess CLI com JSON**: [orchestrator/adapters/nuclei_adapter.py](orchestrator/adapters/nuclei_adapter.py)
- **Subprocess CLI com XML**: [orchestrator/adapters/nmap_adapter.py](orchestrator/adapters/nmap_adapter.py)
- **HTTP API com lifecycle longo**: [orchestrator/adapters/zap_adapter.py](orchestrator/adapters/zap_adapter.py)
- **HTTP API síncrona**: [orchestrator/adapters/github_exposure_adapter.py](orchestrator/adapters/github_exposure_adapter.py)
- **OSINT com clone+scan**: [orchestrator/adapters/gitleaks_adapter.py](orchestrator/adapters/gitleaks_adapter.py)

Ler `orchestrator/adapters/base.py` pra Protocol exato.

## 3. Criar o adapter

Path: `orchestrator/adapters/<name>_adapter.py`.

Template mínimo (subprocess):

```python
"""<NAME> adapter — <descrição curta>."""

from __future__ import annotations

import asyncio
import json  # ou ET pra XML
import shutil
import tempfile
from pathlib import Path
from typing import Any
from uuid import uuid4

import structlog

from orchestrator.domain.schemas import (
    AssetType, Confidence, Evidence, Finding, RawResults,
    ScanHandle, ScanStatus, Severity, Target,
)

log = structlog.get_logger(__name__)


class <Name>Adapter:
    name = "<name>"

    def __init__(self, bin_path: str | None = None) -> None:
        self.bin = bin_path or shutil.which("<binary>") or "<binary>"
        self._tasks: dict[str, asyncio.Task[int]] = {}
        self._outputs: dict[str, Path] = {}

    async def health(self) -> bool:
        try:
            p = await asyncio.create_subprocess_exec(
                self.bin, "--version",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await p.communicate()
            return p.returncode == 0
        except (FileNotFoundError, PermissionError):
            return False

    async def start_scan(self, target: Target, options: dict[str, Any]) -> ScanHandle:
        # validar asset_type
        # criar dir temporário pra output
        # chamar subprocess não-bloqueante
        # guardar task em self._tasks
        ...

    async def poll(self, handle: ScanHandle) -> ScanStatus:
        task = self._tasks.get(handle.native_id)
        if task is None: return ScanStatus.FAILED
        return ScanStatus.DONE if task.done() else ScanStatus.RUNNING

    async def fetch_results(self, handle: ScanHandle) -> RawResults:
        # ler output, parsear
        ...

    async def normalize(self, raw: RawResults) -> list[Finding]:
        findings: list[Finding] = []
        placeholder = uuid4()
        # iterar payload, criar Finding canônico
        return findings
```

Seguir [`.claude/rules/scanners.md`](.claude/rules/scanners.md) — convenções obrigatórias.

## 4. Adicionar fixture e teste

`tests/fixtures/<name>_sample.<ext>` — output real do scanner contra alvo conhecido.
`tests/unit/test_<name>_adapter.py`:

```python
import pytest
from orchestrator.adapters.<name>_adapter import <Name>Adapter
from orchestrator.domain.schemas import RawResults, Severity

@pytest.fixture
def sample_payload():
    return Path("tests/fixtures/<name>_sample.json").read_text()

async def test_normalize_basic(sample_payload):
    adapter = <Name>Adapter()
    raw = RawResults(adapter="<name>", payload=json.loads(sample_payload))
    findings = await adapter.normalize(raw)
    assert len(findings) >= 1
    assert all(f.source_tool == "<name>" for f in findings)
```

## 5. Integrar no pipeline

Editar `orchestrator/jobs/pipelines.py` (scan ativo) ou `orchestrator/jobs/exposure.py` (OSINT) — adicionar instância na lista de adapters padrão.

Não é automático: explicitamente listado.

## 6. Atualizar infra

- **Dockerfile** ([docker/images/kali-toolbox/Dockerfile](docker/images/kali-toolbox/Dockerfile)): adicionar instalação do binário
- **`pyproject.toml`**: dependências Python novas
- **`.env.example`**: novas variáveis (API keys, paths)
- **`orchestrator/config.py`**: schema das envs novas

## 7. Documentar

- README.md: adicionar linha na tabela de adapters
- `docs/architecture.md`: tabela de adapters
- `.claude/skills/cai-scan/SKILL.md`: mencionar novo adapter como opção

## 8. Validar

```bash
make build
pytest tests/unit/test_<name>_adapter.py -v
```

E rodar smoke E2E pra ver que pipeline integrou:

```bash
make smoke  # depois inspecionar reports/ pra confirmar findings do novo adapter
```

## Checklist final

- [ ] `health()` retorna bool, não lança
- [ ] `start_scan` é não-bloqueante
- [ ] `normalize` produz `Finding` canônico — sem campos extras
- [ ] `evidence` tem ao menos descrição + snippet
- [ ] `severity` é heurística do scanner — não enviesada por contexto
- [ ] Teste unitário com fixture passa
- [ ] Pipeline integrado e build do Docker OK
- [ ] README atualizado
