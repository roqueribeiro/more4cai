"""FastAPI app factory.

Entrypoint: `uvicorn orchestrator.main:app --host 0.0.0.0 --port 8080`
ou via `make api`.

Serve também o dashboard UI em `/ui` (StaticFiles) + endpoints `/ui/api/*`.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from orchestrator.ai.observability import log_processor
from orchestrator.api.routers import (
    auth as auth_router,
)
from orchestrator.api.routers import (
    exposure as exposure_router,
)
from orchestrator.api.routers import (
    findings as findings_router,
)
from orchestrator.api.routers import (
    health as health_router,
)
from orchestrator.api.routers import (
    investigate as investigate_router,
)
from orchestrator.api.routers import (
    reports as reports_router,
)
from orchestrator.api.routers import (
    scans as scans_router,
)
from orchestrator.api.routers import (
    targets as targets_router,
)
from orchestrator.api.routers import (
    ui as ui_router,
)
from orchestrator.api.routers import (
    users as users_router,
)
from orchestrator.config import settings


def _setup_logging() -> None:
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            log_processor,  # ring buffer pra UI live logs
            (
                structlog.processors.JSONRenderer()
                if settings.LOG_FORMAT == "json"
                else structlog.dev.ConsoleRenderer()
            ),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _setup_logging()
    log = structlog.get_logger(__name__)

    # cria tabelas (dev SQLite). Em prod usar `alembic upgrade head` antes.
    if settings.DATABASE_URL.startswith("sqlite"):
        from orchestrator.persistence.db import init_db

        await init_db()
        log.info("db.sqlite_init_done")

    # phoenix tracing opt-in
    if settings.PHOENIX_COLLECTOR_ENDPOINT:
        try:
            from orchestrator.ai.agentic.tracing import setup_phoenix

            setup_phoenix(settings.PHOENIX_COLLECTOR_ENDPOINT)
            log.info("phoenix.tracing_enabled")
        except Exception as e:  # noqa: BLE001
            log.warning("phoenix.setup_failed", error=str(e))

    yield


app = FastAPI(
    title="CAI Orchestrator",
    description="Continuous AI Security testing platform",
    version="0.4.0",
    lifespan=lifespan,
)

app.include_router(targets_router.router)
app.include_router(scans_router.router)
app.include_router(findings_router.router)
app.include_router(reports_router.router)
app.include_router(exposure_router.router)
app.include_router(investigate_router.router)
app.include_router(health_router.router)  # /health/full
app.include_router(ui_router.router)  # /ui/api/*
app.include_router(users_router.router)  # /users (admin-only, RBAC)
app.include_router(auth_router.router)  # /auth (OIDC SSO)

# Session cookie pro state/nonce do fluxo OIDC (authlib usa request.session).
# Só montamos o SessionMiddleware quando o OIDC está realmente configurado — assim
# o engine NÃO exige `itsdangerous` (dep transitiva do middleware) quando SSO está
# desligado, que é o caso padrão (demo, self-host sem IdP). Import lazy de propósito.
if settings.OIDC_ISSUER and settings.OIDC_CLIENT_ID and settings.OIDC_CLIENT_SECRET:
    from starlette.middleware.sessions import SessionMiddleware

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SESSION_SECRET or settings.APP_TOKEN,
        same_site="lax",
        https_only=False,
    )

# Static files servindo o dashboard em /ui
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(_STATIC_DIR), html=True), name="ui")


@app.get("/health")
async def health() -> dict:
    """Liveness simples (sem auth, leve). /health/full pra checagem completa."""
    return {"status": "ok", "version": app.version}


@app.get("/")
async def root() -> RedirectResponse:
    """Raiz redireciona pro dashboard."""
    return RedirectResponse(url="/ui/", status_code=302)
