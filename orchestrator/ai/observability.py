"""Observability primitives — log ring buffer + phase emitter + SSE stream.

Singleton in-process. Reseta no restart do orchestrator (ok pra MVP — logs
históricos ficam em `docker logs cai-orchestrator`).
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from datetime import UTC, datetime
from typing import Any

# Ring buffer de logs (últimas 1000 linhas estruturadas)
_LOG_BUFFER: deque[dict[str, Any]] = deque(maxlen=1000)

# Última atualização de fase por scan_id
_PHASE_BUFFER: dict[str, dict[str, Any]] = {}

# Asyncio event que dispara quando algo novo chega (logs ou phase)
_EVENT_SIGNAL: asyncio.Event | None = None


def _signal() -> asyncio.Event:
    """Cria/retorna o event signal (lazy — precisa de loop async)."""
    global _EVENT_SIGNAL
    if _EVENT_SIGNAL is None:
        _EVENT_SIGNAL = asyncio.Event()
    return _EVENT_SIGNAL


def log_processor(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor — appenda no ring buffer e propaga.

    Não modifica `event_dict` (devolve igual). Só escuta.
    """
    snapshot = dict(event_dict)
    snapshot["_received_at"] = datetime.now(UTC).isoformat()
    _LOG_BUFFER.append(snapshot)
    try:
        ev = _signal()
        ev.set()
    except RuntimeError:
        # Sem loop async corrente (ex: import-time logs) — ignora
        pass
    return event_dict


def emit_phase(scan_id: str, phase: str, progress: int | None = None) -> None:
    """Pipeline chama isso em cada transição de fase.

    Não persiste no DB (isso é responsabilidade do `_update_phase` no pipeline);
    apenas notifica consumidores SSE em tempo real.
    """
    _PHASE_BUFFER[scan_id] = {
        "scan_id": scan_id,
        "phase": phase,
        "progress": progress,
        "ts": datetime.now(UTC).isoformat(),
    }
    try:
        _signal().set()
    except RuntimeError:
        pass


def get_recent_logs(limit: int = 200) -> list[dict[str, Any]]:
    """Retorna últimos N logs do buffer (mais recentes no fim)."""
    return list(_LOG_BUFFER)[-limit:]


def get_phase(scan_id: str) -> dict[str, Any] | None:
    return _PHASE_BUFFER.get(scan_id)


async def sse_stream(scan_id: str | None = None, max_idle_seconds: int = 30) -> Any:
    """Async generator que emite linhas SSE (`data: {...}\\n\\n`).

    - Logs novos: emite `event: log` com payload JSON.
    - Phase update do scan_id (se passado): emite `event: phase`.
    - Heartbeat: a cada 15s emite `: keepalive\\n\\n` pra manter conexão viva.
    """
    last_log_idx = len(_LOG_BUFFER)
    last_phase_seen: dict[str, str] = {}

    # primeira emissão: snapshot inicial
    if scan_id and (cur := _PHASE_BUFFER.get(scan_id)):
        yield f"event: phase\ndata: {json.dumps(cur)}\n\n"
        last_phase_seen[scan_id] = cur["phase"]

    while True:
        ev = _signal()
        try:
            await asyncio.wait_for(ev.wait(), timeout=15.0)
        except TimeoutError:
            # heartbeat
            yield ": keepalive\n\n"
            continue
        ev.clear()

        # Novos logs
        cur_len = len(_LOG_BUFFER)
        if cur_len > last_log_idx:
            new = list(_LOG_BUFFER)[last_log_idx - cur_len :]  # slice negativo
            for entry in new:
                # filtro mínimo: descartar mensagens internas do servidor SSE
                if entry.get("event", "").startswith("ui.sse"):
                    continue
                yield f"event: log\ndata: {json.dumps(entry, default=str)}\n\n"
            last_log_idx = cur_len

        # Phase update do scan_id solicitado
        if scan_id and (cur := _PHASE_BUFFER.get(scan_id)):
            if last_phase_seen.get(scan_id) != cur.get("phase") or True:
                # sempre emite — UI filtra. Inclui progress changes.
                yield f"event: phase\ndata: {json.dumps(cur)}\n\n"
                last_phase_seen[scan_id] = cur["phase"]
