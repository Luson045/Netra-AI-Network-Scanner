"""Scan worker: claims pending scans and executes them.

Runnable via: python -m app.workers.scan_worker

Claiming uses a heartbeat/lease so a crashed worker's scans can be reclaimed.
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from datetime import timedelta

from sqlalchemy import select, update

from app.core.config import settings
from app.core.db import dispose_engine, get_session_factory
from app.core.logging import configure_logging, get_logger
from app.models import ScanJob
from app.models.enums import ACTIVE_SCAN_STATUSES
from app.models.scan import utcnow
from app.services.scanner.engine import run_scan

logger = get_logger("app.worker")

WORKER_ID = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"


async def _reclaim_stale_scans(factory) -> int:
    """Re-queue scans whose worker lease expired."""
    cutoff = utcnow() - timedelta(seconds=settings.worker_heartbeat_secs)
    async with factory() as session:
        result = await session.execute(
            update(ScanJob)
            .where(
                ScanJob.status == "running",
                ScanJob.heartbeat_at < cutoff,
            )
            .values(status="pending", worker_id=None, heartbeat_at=None)
        )
        await session.commit()
        return result.rowcount or 0


async def _claim_next_scan(factory) -> int | None:
    """Atomically claim one pending scan, or return None."""
    async with factory() as session:
        result = await session.execute(
            select(ScanJob)
            .where(ScanJob.status == "pending")
            .order_by(ScanJob.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        scan = result.scalar_one_or_none()
        if scan is None:
            return None
        # Claim by moving straight to running; run_scan refreshes timestamps.
        scan.status = "running"
        scan.worker_id = WORKER_ID
        scan.heartbeat_at = utcnow()
        await session.commit()
        return scan.id


async def _heartbeat_loop(scan_id: int, stop: asyncio.Event) -> None:
    """Keep heartbeat_at fresh while a scan is running."""
    factory = get_session_factory()
    while not stop.is_set():
        try:
            async with factory() as session:
                scan = await session.get(ScanJob, scan_id)
                if scan is not None and scan.worker_id == WORKER_ID:
                    scan.heartbeat_at = utcnow()
                    await session.commit()
        except Exception:  # noqa: BLE001
            logger.exception("Heartbeat failed for scan %s", scan_id)
        try:
            await asyncio.wait_for(stop.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass


async def _run_one(scan_id: int) -> None:
    stop = asyncio.Event()
    hb = asyncio.create_task(_heartbeat_loop(scan_id, stop))
    try:
        await run_scan(scan_id, WORKER_ID)
    finally:
        stop.set()
        await asyncio.gather(hb, return_exceptions=True)


async def worker_loop(poll_interval: float | None = None) -> None:
    poll_interval = poll_interval or settings.poll_interval
    configure_logging(settings.log_level)
    factory = get_session_factory()
    logger.info("Scan worker %s started (poll=%.1fs)", WORKER_ID, poll_interval)

    while True:
        try:
            reclaimed = await _reclaim_stale_scans(factory)
            if reclaimed:
                logger.info("Reclaimed %d stale scan(s)", reclaimed)

            scan_id = await _claim_next_scan(factory)
            if scan_id is not None:
                logger.info("Worker %s claimed scan %s", WORKER_ID, scan_id)
                await _run_one(scan_id)
                continue  # check for more work immediately
            await asyncio.sleep(poll_interval)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("Worker loop error; continuing")
            await asyncio.sleep(poll_interval)


def main() -> None:
    configure_logging(settings.log_level)
    try:
        asyncio.run(worker_loop())
    except KeyboardInterrupt:
        logger.info("Worker stopped")


if __name__ == "__main__":
    main()
