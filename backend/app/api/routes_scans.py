"""Scan REST routes + WebSocket progress."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.errors import NotFoundError, ScanStateError
from app.core.utils import progress_hub
from app.models import Asset, Finding, ScanJob
from app.models.enums import ACTIVE_SCAN_STATUSES
from app.models.scan import utcnow
from app.schemas.scan import ScanCreate, ScanHistoryPoint, ScanOut, ScanProgressOut
from app.services.scanner.targets import parse_port_spec, parse_targets

logger = logging.getLogger("app.api.scans")

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/preview")
async def preview_scan(payload: ScanCreate):
    """Validate and summarize an authorized scan without creating a job."""
    networks, hosts = parse_targets(payload.targets)
    ports = parse_port_spec(payload.ports)
    return {
        "targets": networks,
        "host_count": len(hosts),
        "ports": ports,
        "check_count": len(hosts) * len(ports),
    }


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)):
    """Create (queue) a scan job. Targets are validated and authorized now."""
    # Parse targets eagerly so the user gets immediate feedback on bad/forbidden targets.
    networks, _hosts = parse_targets(payload.targets)
    parse_port_spec(payload.ports)

    scan = ScanJob(
        name=payload.name or f"Scan {utcnow().strftime('%Y-%m-%d %H:%M')}",
        target_spec=payload.targets.strip(),
        port_spec=payload.ports,
        targets="\n".join(networks),
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("", response_model=list[ScanOut])
async def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    q = select(ScanJob).order_by(desc(ScanJob.created_at))
    if status:
        q = q.where(ScanJob.status == status)
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/history", response_model=list[ScanHistoryPoint])
async def scan_history(days: int = Query(default=14, ge=1, le=90), db: AsyncSession = Depends(get_db)):
    """Aggregate scan counts, hosts up and findings per day for the chart."""
    since = utcnow() - timedelta(days=days)
    result = await db.execute(
        select(ScanJob).where(ScanJob.created_at >= since).order_by(ScanJob.created_at)
    )
    scans = result.scalars().all()

    by_day: dict[str, dict] = {}
    for s in scans:
        day = s.created_at.date().isoformat()
        bucket = by_day.setdefault(day, {"scans": 0, "hosts_up": 0, "findings": 0})
        bucket["scans"] += 1
        if s.status == "completed":
            bucket["hosts_up"] += s.hosts_up
            bucket["findings"] += s.findings_count

    return [
        ScanHistoryPoint(date=day, **vals) for day, vals in sorted(by_day.items())
    ]


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanJob, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    return scan


@router.get("/{scan_id}/progress", response_model=ScanProgressOut)
async def get_scan_progress(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Polling fallback for scan progress."""
    scan = await db.get(ScanJob, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    return ScanProgressOut(
        scan_id=scan.id,
        status=scan.status,
        total_targets=scan.total_targets,
        completed_targets=scan.completed_targets,
        hosts_up=scan.hosts_up,
        ports_found=scan.ports_found,
        findings_count=scan.findings_count,
        error_message=scan.error_message,
        finished_at=scan.finished_at,
    )


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanJob, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    if scan.status not in ACTIVE_SCAN_STATUSES:
        raise ScanStateError(f"Scan is already {scan.status}")
    scan.status = "cancelled"
    scan.finished_at = utcnow()
    await db.commit()
    await db.refresh(scan)
    return scan


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanJob, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    await db.delete(scan)
    await db.commit()


@router.websocket("/{scan_id}/ws")
async def scan_progress_ws(websocket: WebSocket, scan_id: int):
    """Live progress for one scan. Emits DB snapshots + hub events until terminal state."""
    await websocket.accept()
    factory = _factory()
    hub_q = await progress_hub.subscribe(scan_id)
    try:
        # Initial snapshot
        async with factory() as db:
            scan = await db.get(ScanJob, scan_id)
            if scan is None:
                await websocket.send_json({"error": "scan_not_found"})
                await websocket.close()
                return
            await websocket.send_json(_snapshot(scan))

        while True:
            # Wait for either a hub event or a periodic DB refresh (poll fallback inside WS).
            hub_task = asyncio.create_task(hub_q.get())
            poll_task = asyncio.create_task(asyncio.sleep(2.0))
            done, pending = await asyncio.wait(
                {hub_task, poll_task}, return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()

            async with factory() as db:
                scan = await db.get(ScanJob, scan_id)
                if scan is None:
                    await websocket.send_json({"error": "scan_not_found"})
                    break
                payload = _snapshot(scan)
            if hub_task in done and not hub_task.cancelled():
                try:
                    evt = hub_task.result()
                    payload = {**payload, **{k: v for k, v in evt.items() if v is not None}}
                except Exception:  # noqa: BLE001
                    pass

            await websocket.send_json(payload)

            if scan and scan.status in ("completed", "failed", "cancelled"):
                break
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        logger.exception("WS error for scan %s", scan_id)
    finally:
        await progress_hub.unsubscribe(scan_id, hub_q)


def _snapshot(scan: ScanJob) -> dict:
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "total_targets": scan.total_targets,
        "completed_targets": scan.completed_targets,
        "hosts_up": scan.hosts_up,
        "ports_found": scan.ports_found,
        "findings_count": scan.findings_count,
        "error_message": scan.error_message,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }


def _factory():
    from app.core.db import get_session_factory
    return get_session_factory()
