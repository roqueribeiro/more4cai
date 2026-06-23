"""arq queue config — async jobs sobre Redis."""

from __future__ import annotations

import structlog
from arq.connections import RedisSettings

from orchestrator.config import settings

log = structlog.get_logger(__name__)


def _redis_settings() -> RedisSettings:
    """Constrói RedisSettings a partir de REDIS_URL (`redis://host:port/db`)."""
    return RedisSettings.from_dsn(settings.REDIS_URL)


async def startup(ctx: dict) -> None:
    log.info("worker.startup")


async def shutdown(ctx: dict) -> None:
    log.info("worker.shutdown")


# Late import pra evitar ciclo: queue.py é importado pelos workers,
# que por sua vez importam pipelines.
def _functions() -> list:
    from orchestrator.jobs import workers

    return [
        workers.run_scan_job,
        workers.run_exposure_job,
    ]


class WorkerSettings:
    """Config consumida por `arq orchestrator.jobs.queue.WorkerSettings`."""

    redis_settings = _redis_settings()
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = 4
    job_timeout = 3600  # scans podem ser longos
    keep_result = 3600 * 24
    # arq lê `functions` como ATRIBUTO iterável (não chama um método). Atribuído
    # logo abaixo, após a classe estar definida, pra preservar o late import de
    # `workers` (evita o ciclo queue<->workers) sem quebrar arq >=0.26 (0.28
    # falhava: `'classmethod' object is not iterable`).
    functions: list = []


# Bind após a definição da classe + do módulo: o late import de `workers` roda
# com `queue` já totalmente carregado, então qualquer import indireto de volta
# pra `queue` encontra todos os nomes resolvidos.
WorkerSettings.functions = _functions()
