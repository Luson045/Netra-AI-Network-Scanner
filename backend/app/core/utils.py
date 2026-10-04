"""Small shared helpers: DB init, pagination, WebSocket progress."""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_engine
from app.core.logging import get_logger

logger = get_logger("app.utils")


async def init_db() -> None:
    """Create tables (dev convenience). Production deployments should use Alembic migrations."""
    engine = get_engine()
    from app.models import base  # noqa: F401  (registers mappers)

    async with engine.begin() as conn:
        await conn.run_sync(lambda sync_conn: base.Base.metadata.create_all(sync_conn))
    logger.info("Database schema ensured")


async def safe_init_db(session: AsyncSession | None = None) -> None:
    """init_db that tolerates concurrent/parallel CREATE TABLE (SQLite/Postgres races)."""
    try:
        await init_db()
    except Exception as exc:  # noqa: BLE001
        logger.warning("init_db non-fatal failure: %s", exc)


async def paginate(params) -> tuple[int, int, int]:
    return params.limit, params.offset, params.page


async def _noop() -> None:
    return None


class ScanProgressHub:
    """In-process fan-out of scan progress events to WebSocket subscribers.

    The worker publishes progress to the DB (source of truth); the API also fans out
    live events here for real-time UI updates. In multi-instance deployments this can
    be replaced with Redis pub/sub — the interface stays the same.
    """

    def __init__(self) -> None:
        self._subscribers: dict[int, set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, scan_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers.setdefault(scan_id, set()).add(q)
        return q

    async def unsubscribe(self, scan_id: int, q: asyncio.Queue) -> None:
        async with self._lock:
            subs = self._subscribers.get(scan_id)
            if subs and q in subs:
                subs.discard(q)
            if subs is not None and not subs and scan_id in self._subscribers:
                del self._subscribers[scan_id]

    async def publish(self, scan_id: int, payload: dict[str, Any]) -> None:
        async with self._lock:
            queues = [q for q in self._subscribers.get(scan_id, set())]
        for q in queues:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                # Slow consumer; drop oldest by draining one event.
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                    q.task_done()
                except Exception:
                    pass


progress_hub = ScanProgressHub()
