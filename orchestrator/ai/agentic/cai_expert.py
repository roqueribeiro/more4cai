"""CAI agentic — investigação profunda de findings sob HITL.

Estratégia (Fase 4):
- Container `cai-expert` opt-in com `cai-framework` instalado.
- Quando NÃO disponível, fallback para investigação simples via tool use direto
  com Claude (gateway existente). Mantém compatibilidade pra rodar sem CAI.

Nesta versão (parcial), implementamos o fallback "tool use direto" funcional.
Integração total com cai-framework é marcada com TODO — segue padrão de
abstração que aceita ambos os caminhos.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

import structlog

from orchestrator.ai.gateway import complete
from orchestrator.persistence.models import FindingRow

log = structlog.get_logger(__name__)


_INVESTIGATE_SYSTEM = """\
Você é um agente de investigação de segurança ofensiva, operando em modo HITL.

Você tem acesso a:
- Findings de scanners (ZAP, Nmap, Greenbone, Trivy, Nuclei) com evidências
- Histórico de comandos rodados (read-only)

Sua função: investigar profundamente um finding específico.

Regras:
- Em modo dry_run=true, NÃO execute comandos. Sugira o comando, justifique, mas
  não rode. Retorne plano de investigação como narrativa.
- Em modo dry_run=false (perigoso, exige autorização), você pode propor comandos
  que serão executados pelo orquestrador no kali-toolbox container, com cap_drop
  e network policy. Mesmo assim, peça confirmação por etapa.
- Respeite blast radius: nunca propor scan ativo de produção, fuzzing pesado,
  brute force ou qualquer ação que possa derrubar serviço.
- Saída: JSON com plan, evidence_correlation, risk_assessment, false_positive_likelihood.

Em pentest comercial: respeite o escopo escrito do contrato; nunca proponha
comandos que extrapolem hosts/rotas autorizadas pelo cliente.
"""


async def investigate_finding(
    finding: FindingRow,
    *,
    extra_instructions: str | None = None,
    dry_run: bool = True,
    max_steps: int = 10,
) -> dict[str, Any]:
    """Investigação profunda. Tenta CAI framework; cai pro fallback se não disponível."""

    if _cai_framework_available():
        try:
            return await _investigate_with_cai(finding, extra_instructions, dry_run, max_steps)
        except Exception as e:  # noqa: BLE001
            log.warning("cai.framework_failed_fallback", error=str(e))

    return await _investigate_fallback(finding, extra_instructions, dry_run)


def _cai_framework_available() -> bool:
    try:
        import cai  # type: ignore[import-not-found]  # noqa: F401

        return True
    except ImportError:
        return False


async def _investigate_with_cai(
    finding: FindingRow,
    extra: str | None,
    dry_run: bool,
    max_steps: int,
) -> dict[str, Any]:
    """TODO Fase 4: integração completa com cai-framework.

    Esqueleto: criar Agent CAI com tools (linux_cmd, http_request, websearch),
    configurar LLM via litellm, rodar com HITL=True, dry_run=dry_run, max_turns=max_steps.

    Por hora, levantamos NotImplementedError pra cair no fallback.
    """
    raise NotImplementedError("CAI framework integration pending — using fallback")


async def _investigate_fallback(
    finding: FindingRow,
    extra: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    """Sem CAI: usa Claude direto via gateway. Sem tool use ativo, só raciocínio."""

    user = f"""\
FINDING:
- id: {finding.id}
- tool: {finding.source_tool}
- title: {finding.title}
- severity: {finding.severity}
- payload: {finding.payload}

dry_run={dry_run}
{f"INSTRUÇÕES ADICIONAIS DO OPERADOR: {extra}" if extra else ""}

Investigue. Retorne JSON com:
- plan: lista de passos de investigação (cada um com command_suggestion, rationale)
- evidence_correlation: o que sustenta o finding, o que falta
- risk_assessment: impacto pra um banco BR
- false_positive_likelihood: 0.0-1.0
- next_actions: passos seguros que o operador deveria tomar
"""

    text = await complete(
        [
            {"role": "system", "content": _INVESTIGATE_SYSTEM},
            {"role": "user", "content": user},
        ],
        cache_system=True,
        max_tokens=2048,
    )

    return {
        "transcript": [{"role": "assistant", "content": text}],
        "final_assessment": text,
        "trace_url": None,
    }


async def kali_run_readonly(cmd: list[str], timeout: float = 60.0) -> dict[str, Any]:
    """Executa comando read-only no kali-toolbox via docker exec.

    Permite apenas comandos da allowlist (curl, dig, whois, host, nslookup, etc.).
    Para Fase 4 com dry_run=False — ainda assim com revisão humana.
    """
    SAFE_BINS = {"curl", "wget", "dig", "host", "nslookup", "whois", "openssl", "ping"}
    if not cmd or cmd[0] not in SAFE_BINS:
        return {"error": f"comando '{cmd[0] if cmd else ''}' não está na allowlist read-only"}

    docker = shutil.which("docker")
    if not docker:
        return {"error": "docker não disponível"}

    full = [docker, "exec", "cai-kali-toolbox", *cmd]
    try:
        proc = await asyncio.create_subprocess_exec(
            *full,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "exit_code": proc.returncode,
            "stdout": stdout.decode(errors="replace")[:8000],
            "stderr": stderr.decode(errors="replace")[:2000],
        }
    except TimeoutError:
        return {"error": "timeout"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
