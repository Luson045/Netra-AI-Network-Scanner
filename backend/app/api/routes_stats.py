"""Dashboard stats & risk/anomaly overview routes."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.models import Asset, Finding, ScanJob, Service
from app.models.enums import FindingSeverity, FindingStatus, SEVERITY_ORDER
from app.models.scan import utcnow
from app.schemas.stats import AnomalyPoint, OverviewStats, SeverityCount, TopOpenPort

router = APIRouter(tags=["stats"])


@router.get("/stats/overview", response_model=OverviewStats)
async def overview(db: AsyncSession = Depends(get_db)):
    now = utcnow()
    day_ago = now - timedelta(hours=24)

    total_assets = (await db.execute(select(func.count()).select_from(Asset))).scalar() or 0
    alive_assets = (
        await db.execute(select(func.count()).select_from(Asset).where(Asset.is_alive.is_(True)))
    ).scalar() or 0
    total_services = (await db.execute(select(func.count()).select_from(Service))).scalar() or 0
    open_findings = (
        await db.execute(select(func.count()).select_from(Finding).where(Finding.status == "open"))
    ).scalar() or 0
    high_or_critical = (
        await db.execute(
            select(func.count())
            .select_from(Finding)
            .where(Finding.status == "open", Finding.severity.in_(["high", "critical"]))
        )
    ).scalar() or 0
    scans_24h = (
        await db.execute(select(func.count()).select_from(ScanJob).where(ScanJob.created_at >= day_ago))
    ).scalar() or 0

    max_risk = (await db.execute(select(func.max(Asset.risk_score)))).scalar() or 0
    avg_risk = (await db.execute(select(func.avg(Asset.risk_score)))).scalar() or 0.0

    return OverviewStats(
        total_assets=total_assets,
        alive_assets=alive_assets,
        total_services=total_services,
        open_findings=open_findings,
        high_or_critical_findings=high_or_critical,
        scans_24h=scans_24h,
        max_risk_score=max_risk,
        avg_risk_score=round(float(avg_risk), 1),
    )


@router.get("/stats/severities", response_model=list[SeverityCount])
async def severity_breakdown(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding.severity, func.count())
        .where(Finding.status == "open")
        .group_by(Finding.severity)
    )
    rows = result.all()
    order = ["critical", "high", "medium", "low", "info"]
    counts = {sev: cnt for sev, cnt in rows}
    return [SeverityCount(severity=sev, count=counts.get(sev, 0)) for sev in order]


@router.get("/stats/top-ports", response_model=list[TopOpenPort])
async def top_open_ports(limit: int = Query(default=10, ge=1, le=50), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Service.port, Service.service_name, func.count())
        .where(Service.state == "open")
        .group_by(Service.port, Service.service_name)
        .order_by(func.count().desc())
        .limit(limit)
    )
    rows = result.all()
    return [TopOpenPort(port=p, service_name=n, count=c) for p, n, c in rows]


@router.get("/stats/anomalies", response_model=list[AnomalyPoint])
async def anomaly_overview(limit: int = Query(default=30, ge=1, le=100), db: AsyncSession = Depends(get_db)):
    """Per-scan deviation from this deployment's own baseline.

    Baseline = mean/stdev of open ports found by previous completed scans.
    |z| >= 3 is flagged as anomalous. Deterministic and explainable.
    """
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.status == "completed")
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
    )
    scans = list(reversed(result.scalars().all()))
    if len(scans) < 2:
        return []

    counts = [float(s.ports_found) for s in scans]
    mu = sum(counts) / len(counts)
    var = sum((x - mu) ** 2 for x in counts) / (len(counts) - 1) if len(counts) > 1 else 0.0
    sigma = var ** 0.5

    points: list[AnomalyPoint] = []
    for s, current in zip(scans, counts):
        z = (current - mu) / sigma if sigma else 0.0
        points.append(
            AnomalyPoint(
                scan_id=s.id,
                created_at=s.created_at.isoformat(),
                hosts_up=s.hosts_up,
                ports_found=int(current),
                findings_count=s.findings_count,
                port_delta_vs_baseline=int(current - mu),
                is_anomaly=abs(z) >= 3.0,
                z_score=round(z, 2),
            )
        )
    return points
