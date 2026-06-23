"""LLM gateway via litellm.

Wraps litellm.acompletion with:
  - Anthropic prompt caching (system prompt marcado como ephemeral cache)
  - Fallback automático: se o backend "primário" (local) falhar, cai pro modelo de API
  - Telemetria persistida via `AIRun` (latência, tokens, sucesso, fallback)

litellm aceita o mesmo dict OpenAI-compat para Claude, OpenAI, Ollama, LM Studio,
OpenRouter, Azure. Trocar provider é só mudar `model=`.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any
from uuid import UUID

import litellm
import structlog
from litellm import acompletion
from litellm.exceptions import APIConnectionError, APIError, ServiceUnavailableError

from orchestrator.config import settings

# Reasoning models (claude-opus-4-*, OpenAI o-series) reject params like
# `temperature` ≠ 1. Let litellm silently DROP any param the selected model
# doesn't support instead of raising UnsupportedParamsError — otherwise AI
# triage fails for the whole batch (seen live: opus-4-7 + temperature=0.2).
litellm.drop_params = True

log = structlog.get_logger(__name__)


_CACHEABLE_MARK = {"cache_control": {"type": "ephemeral"}}


def _wrap_cacheable(text: str) -> list[dict[str, Any]]:
    """Marca um bloco de texto como cacheable (Anthropic prompt caching)."""
    return [{"type": "text", "text": text, **_CACHEABLE_MARK}]


def _normalize_messages(
    messages: Sequence[dict[str, Any]], cache_system: bool
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if cache_system and m.get("role") == "system" and isinstance(m.get("content"), str):
            out.append({"role": "system", "content": _wrap_cacheable(m["content"])})
        else:
            out.append(dict(m))
    return out


async def complete(
    messages: Sequence[dict[str, Any]],
    *,
    model: str | None = None,
    response_format: dict[str, Any] | None = None,
    cache_system: bool = True,
    max_tokens: int = 4096,
    temperature: float = 0.2,
    api_base: str | None = None,
    purpose: str = "unknown",
    scan_id: UUID | None = None,
    finding_count: int = 0,
) -> str:
    """Chama LLM. Tenta `model` (default `settings.LLM_MODEL`); cai pro fallback se quebrar.

    Args:
        purpose: rótulo da chamada — `triage`/`investigation`/`dedup`/`narrative`/...
        scan_id: associação opcional pra telemetria por scan.
        finding_count: nº de findings nesse batch (telemetria).

    Returns:
        O texto da resposta (o `.choices[0].message.content`).
    """
    primary = model or settings.LLM_MODEL
    fallback = settings.LLM_FALLBACK_MODEL
    msg_list = _normalize_messages(messages, cache_system)

    extra = _build_extra(response_format, api_base, primary)
    primary_api_base = extra.get("api_base")

    # tentativa primária
    t0 = time.perf_counter()
    try:
        log.debug("llm.call", model=primary, api_base=primary_api_base, purpose=purpose)
        r = await acompletion(
            model=primary,
            messages=msg_list,
            max_tokens=max_tokens,
            temperature=temperature,
            **extra,
        )
        latency_ms = int((time.perf_counter() - t0) * 1000)
        text = _extract_text(r)
        await _persist_ai_run(
            scan_id=scan_id,
            purpose=purpose,
            model=primary,
            api_base=primary_api_base,
            response=r,
            latency_ms=latency_ms,
            finding_count=finding_count,
            success=True,
            error=None,
        )
        return text
    except (APIConnectionError, ServiceUnavailableError, APIError, TimeoutError) as e:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        log.warning(
            "llm.primary_failed",
            error=str(e),
            model=primary,
            fallback=fallback,
            latency_ms=latency_ms,
        )
        # grava AIRun do primário como falha
        await _persist_ai_run(
            scan_id=scan_id,
            purpose=purpose,
            model=primary,
            api_base=primary_api_base,
            response=None,
            latency_ms=latency_ms,
            finding_count=finding_count,
            success=False,
            error=str(e)[:500],
        )

        if fallback and fallback != primary:
            # Fallback NÃO usa o api_base local — vai pro provider cloud
            fallback_extra = _build_extra(response_format, None, fallback)
            t1 = time.perf_counter()
            r = await acompletion(
                model=fallback,
                messages=msg_list,
                max_tokens=max_tokens,
                temperature=temperature,
                **fallback_extra,
            )
            fallback_latency = int((time.perf_counter() - t1) * 1000)
            text = _extract_text(r)
            await _persist_ai_run(
                scan_id=scan_id,
                purpose=f"{purpose}.fallback",
                model=fallback,
                api_base=fallback_extra.get("api_base"),
                response=r,
                latency_ms=fallback_latency,
                finding_count=finding_count,
                success=True,
                error=None,
            )
            return text
        raise


def _build_extra(
    response_format: dict[str, Any] | None,
    api_base: str | None,
    model: str,
) -> dict[str, Any]:
    """Monta kwargs extras pro acompletion.

    Para LM Studio / Ollama (OpenAI-compat local), aplica api_base +
    api_key dummy. Também ajusta `response_format`: LM Studio rejeita
    `json_object`; confiamos no parser de fallback em `complete_json`.
    """
    extra: dict[str, Any] = {}

    effective_base = api_base if api_base is not None else (settings.LLM_API_BASE or None)
    is_local_backend = bool(effective_base)

    if effective_base:
        extra["api_base"] = effective_base
        # LM Studio ignora a chave; litellm exige uma string. Usar configurada ou dummy.
        extra["api_key"] = settings.LLM_API_KEY or "lm-studio"

    if response_format is not None:
        # LM Studio (até 0.4.x) só aceita 'json_schema'/'text'; pular se for local.
        # `complete_json` faz parsing tolerante via regex de fallback.
        if is_local_backend and response_format.get("type") == "json_object":
            log.debug("llm.response_format_skipped_for_local_backend", model=model)
        else:
            extra["response_format"] = response_format

    return extra


async def complete_json(
    messages: Sequence[dict[str, Any]],
    *,
    model: str | None = None,
    cache_system: bool = True,
    max_tokens: int = 4096,
    purpose: str = "unknown",
    scan_id: UUID | None = None,
    finding_count: int = 0,
) -> dict[str, Any]:
    """Como complete(), mas força JSON e parseia."""
    text = await complete(
        messages,
        model=model,
        response_format={"type": "json_object"},
        cache_system=cache_system,
        max_tokens=max_tokens,
        purpose=purpose,
        scan_id=scan_id,
        finding_count=finding_count,
    )
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # tentativa 1: extrair primeiro objeto JSON balanceado
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
        # tentativa 2: output truncado de modelo de reasoning. Recortar
        # array `triages` e fechar manualmente o último objeto incompleto.
        recovered = _recover_truncated_triages(text)
        if recovered is not None:
            log.warning(
                "llm.json_recovered_from_truncation", items=len(recovered.get("triages", []))
            )
            return recovered
        raise


def _recover_truncated_triages(text: str) -> dict[str, Any] | None:
    """Tenta recuperar `{"triages": [...]}` de resposta cortada por max_tokens.

    Estratégia: localiza `"triages": [`, varre objetos completos até encontrar
    um incompleto e descarta o último. Falha silenciosa retorna None.
    """
    key_idx = text.find('"triages"')
    if key_idx < 0:
        return None
    arr_idx = text.find("[", key_idx)
    if arr_idx < 0:
        return None
    depth = 0
    in_str = False
    escape = False
    items: list[dict[str, Any]] = []
    obj_start = -1
    i = arr_idx + 1
    while i < len(text):
        c = text[i]
        if escape:
            escape = False
        elif c == "\\":
            escape = True
        elif c == '"':
            in_str = not in_str
        elif not in_str:
            if c == "{":
                if depth == 0:
                    obj_start = i
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0 and obj_start >= 0:
                    chunk = text[obj_start : i + 1]
                    try:
                        items.append(json.loads(chunk))
                    except json.JSONDecodeError:
                        pass
                    obj_start = -1
            elif c == "]" and depth == 0:
                break
        i += 1
    if not items:
        return None
    return {"triages": items}


def _extract_text(response: Any) -> str:
    """litellm retorna ModelResponse OpenAI-compat."""
    try:
        return response.choices[0].message.content or ""
    except (AttributeError, IndexError, KeyError):
        return str(response)


async def _persist_ai_run(
    *,
    scan_id: UUID | None,
    purpose: str,
    model: str,
    api_base: str | None,
    response: Any,
    latency_ms: int,
    finding_count: int,
    success: bool,
    error: str | None,
) -> None:
    """Best-effort: grava telemetria. Falha não impacta a chamada LLM."""
    try:
        from orchestrator.persistence.db import session
        from orchestrator.persistence.models import AIRun

        usage = _extract_usage(response) if response is not None else {}
        run = AIRun(
            scan_id=scan_id,
            purpose=purpose,
            model=model,
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            cache_creation_tokens=usage.get("cache_creation_tokens", 0),
            cache_read_tokens=usage.get("cache_read_tokens", 0),
            latency_ms=latency_ms,
            finding_count=finding_count,
            success=success,
            error=error,
        )
        async with session() as s:
            s.add(run)
            await s.commit()
        log.debug(
            "ai_run.persisted",
            purpose=purpose,
            model=model,
            api_base=api_base,
            latency_ms=latency_ms,
            tokens=usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0),
            success=success,
        )
    except Exception as e:  # noqa: BLE001
        log.warning("ai_run.persist_failed", error=str(e))


def _extract_usage(response: Any) -> dict[str, int]:
    """Extrai tokens do litellm response. Robusto a variações entre providers."""
    try:
        u = response.usage
        # `u` pode ser CompletionUsage ou dict-like
        out = {
            "prompt_tokens": int(getattr(u, "prompt_tokens", 0) or 0),
            "completion_tokens": int(getattr(u, "completion_tokens", 0) or 0),
        }
        # Anthropic via litellm expõe cache tokens em prompt_tokens_details
        details = getattr(u, "prompt_tokens_details", None)
        if details is not None:
            out["cache_creation_tokens"] = int(getattr(details, "cached_tokens", 0) or 0)
        # alguns providers não retornam cache_*; ok zero
        return out
    except (AttributeError, TypeError, ValueError):
        return {}
