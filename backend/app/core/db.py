"""Async SQLAlchemy engine/session, shared by API and worker."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _database_url() -> str:
    # Allow explicit env override at import time (docker-compose sets DATABASE_URL).
    return os.environ.get("DATABASE_URL") or _settings_database_url()


def _settings_database_url() -> str:
    from app.core.config import settings

    return settings.database_url


def _ensure_sqlite_dir(url: str) -> None:
    """SQLite cannot create its file inside a missing directory - make sure it exists."""
    if not url.startswith("sqlite"):
        return
    if "///" in url:
        path = url.split("///", 1)[1]
    else:
        path = url.split(":", 1)[-1]
    if not path or path == ":memory:":
        return
    import os

    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)


def get_engine() -> AsyncEngine:
    global _engine, _session_factory
    if _engine is None:
        url = _database_url()
        _ensure_sqlite_dir(url)
        _engine = create_async_engine(url, echo=False, pool_pre_ping=True)
        _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    get_engine()  # ensure initialised
    return _session_factory  # type: ignore[return-value]


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Async context manager yielding a session with commit/rollback semantics."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency (async generator; FastAPI manages its lifecycle)."""
    factory = get_session_factory()

    async with factory() as session:
        yield session


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
