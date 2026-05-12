"""Async SQLAlchemy/SQLModel engine.

Suporta SQLite (dev) e Postgres (prod) via DATABASE_URL.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from orchestrator.config import settings

_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    # SQLite com aiosqlite precisa de conn args para statement timeout etc;
    # Postgres com asyncpg roda nativo.
)

_session_factory = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    """Cria as tabelas (apenas para dev/SQLite). Em prod, usar alembic."""
    async with _engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


async def dispose_db() -> None:
    await _engine.dispose()


@asynccontextmanager
async def session() -> AsyncGenerator[AsyncSession, None]:
    async with _session_factory() as s:
        yield s


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency."""
    async with _session_factory() as s:
        yield s
