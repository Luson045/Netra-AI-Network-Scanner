"""Scan REST routes + WebSocket progress."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.config import settings
from app.core.errors import NotFoundError, ScanStateError, ValidationError
from app.core.utils import progress_hub
from app.models import Asset, DeepScanRun, Finding, ScanJob, ScanObservation, Service
from app.models.enums import ACTIVE_SCAN_STATUSES
from app.models.scan import utcnow
from app.schemas.scan import ScanCreate, ScanHistoryPoint, ScanOut, ScanProgressOut
from app.schemas.pipeline import ScanPipelineOut, ScanPlan, ScanPlanInput
from app.models import ScanPipelineRun
from app.services.pipeline import build_scan_plan
from app.schemas.deep_scan import (
    DeepScanApproval,
    DeepScanCreate,
    DeepScanQueued,
    DeepScanResult,
)
from app.services.deep_agents import (
    agent_candidate_ports,
    analyze_deep_scan,
    create_agent_port_plan,
)
from app.services.analysis.risk import compute_asset_risk
from app.services.analysis.rules import run_analysis_rules

logger = logging.getLogger("app.api.scans")

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/preview")
async def preview_scan(payload: ScanCreate):
    """Validate and summarize an authorized scan without creating a job."""
    plan = build_scan_plan(payload)
    return {
        "targets": plan.targets,
        "host_count": len(plan.host_ips),
        "ports": plan.ports,
        "check_count": plan.check_count,
    }


@router.post("/plan", response_model=ScanPlan)
async def plan_scan(payload: ScanPlanInput):
    """Parse either a ScanCreate request or explicit plain-text scope."""
    return build_scan_plan(payload.scan)


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)):
    """Create (queue) a scan job. Targets are validated and authorized now."""
    plan = build_scan_plan(payload)

    scan = ScanJob(
        name=payload.name or f"Scan {utcnow().strftime('%Y-%m-%d %H:%M')}",
        target_spec=payload.targets.strip(),
        port_spec=payload.ports,
        targets="\n".join(plan.targets),
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


@router.post("/deep/plan")
async def plan_deep_scan(payload: DeepScanCreate):
    """Ask the local planning agent to propose a bounded port plan for review."""
    plan, model = await create_agent_port_plan(payload.targets, payload.name)
    return {"plan": {**plan, "model": model}}


@router.post("/deep", response_model=DeepScanQueued, status_code=201)
async def create_deep_scan(payload: DeepScanApproval, db: AsyncSession = Depends(get_db)):
    """Queue a user-approved local-agent port plan after revalidating its scope."""
    if len(set(payload.ports)) != len(payload.ports) or not set(payload.ports).issubset(
        agent_candidate_ports()
    ):
        raise ValidationError("Deep Scan ports must come from the agent's approved port list")
    validated = build_scan_plan(
        ScanCreate(
            targets=payload.targets,
            ports=",".join(map(str, payload.ports)),
            name=payload.name,
        )
    )
    plan = {
        "target_spec": validated.target_spec,
        "targets": validated.targets,
        "host_ips": validated.host_ips,
        "ports": validated.ports,
        "check_count": validated.check_count,
        "rationale": payload.rationale,
    }
    model = settings.ollama_model
    scan = ScanJob(
        name=payload.name or f"Deep scan {utcnow().strftime('%Y-%m-%d %H:%M')}",
        target_spec=validated.target_spec,
        port_spec=",".join(map(str, validated.ports)),
        targets="\n".join(validated.targets),
        status="pending",
    )
    db.add(scan)
    await db.flush()
    db.add(DeepScanRun(scan_id=scan.id, plan=plan, model=model))
    await db.commit()
    await db.refresh(scan)
    scan.deep_scan = True
    return DeepScanQueued(scan=scan, plan={**plan, "model": model})


@router.post("/{scan_id}/deep-analysis", response_model=DeepScanResult)
async def run_deep_scan_analysis(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanJob, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    if scan.status != "completed":
        raise ScanStateError("Deep Scan analysis is available after the scan completes")
    agent_run = await db.get(DeepScanRun, scan_id)
    if agent_run is None:
        raise ScanStateError("This scan was not created as a Deep Scan")

    if agent_run.analysis is None:
        pipeline = await db.get(ScanPipelineRun, scan_id)
        if pipeline is None:
            raise ScanStateError("Measured scan results are not available for analysis")
        pipeline_data = {
            "evidence_changes": pipeline.evidence_changes,
            "review_order": pipeline.review_order,
            "verifications": pipeline.verifications,
        }
        analysis, model = await analyze_deep_scan(
            agent_run.plan, pipeline_data, scan.name
        )
        agent_run.analysis = analysis
        agent_run.model = model
        agent_run.analyzed_at = utcnow()
        await db.commit()

    return DeepScanResult(
        scan_id=scan_id,
        plan={**agent_run.plan, "model": agent_run.model},
        analysis=agent_run.analysis,
        model=agent_run.model,
        analyzed_at=agent_run.analyzed_at.isoformat() if agent_run.analyzed_at else None,
    )


@router.get("/{scan_id}/pipeline", response_model=ScanPipelineOut)
async def get_scan_pipeline(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Return the persisted change analysis, review order, and claim checks."""
    scan = await db.get(ScanJob, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    pipeline = await db.get(ScanPipelineRun, scan_id)
    if pipeline is None:
        raise ScanStateError("Pipeline results are available after the scan completes")
    return pipeline


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
    scans = result.scalars().all()
    deep_runs = await db.execute(
        select(DeepScanRun.scan_id).where(DeepScanRun.scan_id.in_([scan.id for scan in scans]))
    ) if scans else None
    deep_ids = set(deep_runs.scalars().all()) if deep_runs is not None else set()
    for scan in scans:
        scan.deep_scan = scan.id in deep_ids
    return scans


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
    scan.deep_scan = await db.get(DeepScanRun, scan_id) is not None
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


@router.delete("")
async def delete_scan_history(db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(select(ScanJob))).scalars().all()
    active = [scan.id for scan in scans if scan.status in ACTIVE_SCAN_STATUSES]
    removable = [scan.id for scan in scans if scan.status not in ACTIVE_SCAN_STATUSES]
    await _delete_scan_records(db, removable, rebuild_inventory=False)
    for model in (ScanPipelineRun, ScanObservation, DeepScanRun):
        statement = delete(model)
        if active:
            statement = statement.where(model.scan_id.not_in(active))
        await db.execute(statement)
    await db.execute(delete(Finding))
    await db.execute(delete(Service))
    await db.execute(delete(Asset))
    await db.commit()
    return {"deleted_count": len(removable), "retained_active_count": len(active)}


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanJob, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    if scan.status in ACTIVE_SCAN_STATUSES:
        raise ScanStateError("Stop the scan before deleting it from history")
    await _delete_scan_records(db, [scan_id])
    await db.commit()


async def _delete_scan_records(
    db: AsyncSession, scan_ids: list[int], *, rebuild_inventory: bool = True
) -> None:
    if not scan_ids:
        return
    await db.execute(delete(ScanPipelineRun).where(ScanPipelineRun.scan_id.in_(scan_ids)))
    await db.execute(delete(ScanObservation).where(ScanObservation.scan_id.in_(scan_ids)))
    await db.execute(delete(DeepScanRun).where(DeepScanRun.scan_id.in_(scan_ids)))
    await db.execute(delete(Finding).where(Finding.scan_id.in_(scan_ids)))
    await db.execute(delete(ScanJob).where(ScanJob.id.in_(scan_ids)))
    if rebuild_inventory:
        await _rebuild_inventory_from_history(db)


async def _rebuild_inventory_from_history(db: AsyncSession) -> None:
    """Keep inventory supported by retained observations and remove deleted-only data."""
    observations = (
        await db.execute(
            select(ScanObservation).order_by(
                desc(ScanObservation.observed_at), desc(ScanObservation.id)
            )
        )
    ).scalars().all()
    latest_host: dict[str, ScanObservation] = {}
    latest_alive_at: dict[str, datetime] = {}
    latest_port_check: dict[tuple[str, int], tuple[ScanObservation, dict]] = {}
    for observation in observations:
        latest_host.setdefault(observation.ip, observation)
        if observation.host_alive:
            latest_alive_at.setdefault(observation.ip, observation.observed_at)
        for check in observation.port_checks or []:
            key = (observation.ip, int(check["port"]))
            latest_port_check.setdefault(key, (observation, check))

    assets = (await db.execute(select(Asset))).scalars().all()
    assets_by_ip = {asset.ip: asset for asset in assets}
    assets_by_id = {asset.id: asset for asset in assets}
    services = (await db.execute(select(Service))).scalars().all()
    services_by_key = {}
    for service in services:
        asset = assets_by_id.get(service.asset_id)
        if asset is not None and latest_alive_at.get(asset.ip) is not None:
            services_by_key[(asset.ip, service.port)] = service

    for asset in assets:
        latest = latest_host.get(asset.ip)
        last_alive_at = latest_alive_at.get(asset.ip)
        if latest is None or last_alive_at is None:
            await db.execute(delete(Service).where(Service.asset_id == asset.id))
            await db.delete(asset)
            continue

        asset.is_alive = latest.host_alive
        asset.last_seen = last_alive_at
        if latest.host_alive:
            open_ports = [
                {
                    "port": int(check["port"]),
                    "service": check.get("service"),
                    "banner": check.get("banner"),
                }
                for check in latest.port_checks or []
                if check.get("state") == "open"
            ]
            asset.risk_score = compute_asset_risk(
                run_analysis_rules(asset.ip, open_ports), open_ports
            )

    for key, service in services_by_key.items():
        observation_check = latest_port_check.get(key)
        if observation_check is None or observation_check[1].get("state") != "open":
            await db.delete(service)
            continue
        observation, check = observation_check
        service.state = "open"
        service.last_seen = observation.observed_at
        service.service_name = check.get("service") or service.service_name
        service.banner = check.get("banner") or service.banner

    for (ip, port), (observation, check) in latest_port_check.items():
        if check.get("state") != "open" or (ip, port) in services_by_key:
            continue
        asset = assets_by_ip.get(ip)
        if asset is not None and latest_alive_at.get(ip) is not None:
            db.add(
                Service(
                    asset_id=asset.id,
                    port=port,
                    service_name=check.get("service"),
                    banner=check.get("banner"),
                    state="open",
                    first_seen=observation.observed_at,
                    last_seen=observation.observed_at,
                )
            )


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
