"""Scan engine: executes one scan job end-to-end and persists results.

Flow:
 1. Mark running, write normalized targets.
 2. Discover alive hosts (pluggable DiscoveryBackend).
 3. For each alive host, check ports (safe TCP connect only).
 4. Upsert Assets + Services, run analysis rules -> Findings, compute risk.
 5. Update aggregate counters, mark completed, publish progress.
"""

from __future__ import annotations

import asyncio
import time

from sqlalchemy import select

from app.core.config import settings
from app.core.logging import get_logger
from app.models import Asset, Finding, ScanJob, Service
from app.models.enums import FindingStatus, FindingSeverity
from app.models.scan import utcnow
from app.services.analysis.rules import run_analysis_rules
from app.services.analysis.risk import compute_asset_risk
from app.services.scanner.checks import check_host
from app.services.scanner.targets import parse_port_spec, parse_targets
from app.core.utils import progress_hub

logger = get_logger("app.scanner.engine")


async def _upsert_asset(session, ip: str, hostname: str | None = None) -> Asset:
    result = await session.execute(select(Asset).where(Asset.ip == ip, Asset.hostname.is_(None)))
    asset = result.scalar_one_or_none()
    if asset is None:
        asset = Asset(ip=ip, hostname=hostname, is_alive=True)
        session.add(asset)
        await session.flush()
    else:
        asset.last_seen = utcnow()
        asset.is_alive = True
        if hostname and not asset.hostname:
            asset.hostname = hostname
    return asset


async def _upsert_service(session, asset_id: int, port: int, name: str | None,
                          banner: str | None) -> Service:
    result = await session.execute(
        select(Service).where(Service.asset_id == asset_id, Service.port == port)
    )
    svc = result.scalar_one_or_none()
    now = utcnow()
    if svc is None:
        svc = Service(asset_id=asset_id, port=port, service_name=name, banner=banner,
                      state="open", first_seen=now, last_seen=now)
        session.add(svc)
        await session.flush()
    else:
        svc.state = "open"
        svc.last_seen = now
        if name and not svc.service_name:
            svc.service_name = name
        if banner and not svc.banner:
            svc.banner = banner
    return svc


async def run_scan(scan_id: int, worker_id: str) -> None:
    """Execute the scan job with the given id. Raises on unrecoverable errors."""
    factory = _session_factory()
    started = time.monotonic()
    async with factory() as session:
        scan = await session.get(ScanJob, scan_id)
        if scan is None:
            raise RuntimeError(f"Scan {scan_id} not found")

        # Mark running
        scan.status = "running"
        scan.started_at = utcnow()
        scan.worker_id = worker_id
        scan.heartbeat_at = utcnow()
        await session.commit()

        try:
            networks, hosts = parse_targets(scan.target_spec)
            ports = parse_port_spec(scan.port_spec)
            scan.targets = "\n".join(networks)
            scan.total_targets = len(hosts)
            await session.commit()

            # --- discovery ---
            backend = _discovery_backend()
            alive_map = await backend.discover(hosts, ports)
            alive_ips = [ip for ip, alive in alive_map.items() if alive]
            scan.hosts_up = len(alive_ips)
            scan.completed_targets = len(hosts)
            scan.heartbeat_at = utcnow()
            await session.commit()
            await progress_hub.publish(scan_id, _progress_payload(scan))

            port_results_by_host: dict[str, list] = {}
            if alive_ips:
                sem = asyncio.Semaphore(settings.scan_concurrency)

                async def _probe(ip: str):
                    async with sem:
                        port_results_by_host[ip] = await check_host(ip, ports)

                await asyncio.gather(*(_probe(ip) for ip in alive_ips))

            # --- persist assets/services ---
            hosts_up = 0
            ports_found = 0
            assets_by_ip: dict[str, Asset] = {}
            for ip in alive_ips:
                results = port_results_by_host.get(ip, [])
                open_results = [r for r in results if r.state == "open"]
                if not open_results:
                    continue
                hosts_up += 1
                asset = await _upsert_asset(session, ip)
                assets_by_ip[ip] = asset
                for r in open_results:
                    await _upsert_service(session, asset.id, r.port, r.service_name, r.banner)
                    ports_found += 1

            # mark hosts not seen this round as not alive
            if assets_by_ip:
                all_assets = (await session.execute(select(Asset))).scalars().all()
                for a in all_assets:
                    if a.ip not in assets_by_ip:
                        a.is_alive = False

            await session.commit()

            # --- analysis ---
            findings_count = 0
            max_risk = 0
            risk_sum = 0.0
            risk_n = 0
            for ip, asset in assets_by_ip.items():
                open_ports = [
                    {"port": r.port, "service": r.service_name, "banner": r.banner}
                    for r in port_results_by_host.get(ip, []) if r.state == "open"
                ]
                found = run_analysis_rules(ip, open_ports)
                for f in found:
                    session.add(Finding(
                        scan_id=scan_id,
                        asset_id=asset.id,
                        rule_id=f["rule_id"],
                        title=f["title"],
                        severity=f["severity"],
                        description=f["description"],
                        recommendation=f["recommendation"],
                        evidence=f.get("evidence"),
                    ))
                    findings_count += 1
                risk = compute_asset_risk(found, open_ports)
                asset.risk_score = risk
                max_risk = max(max_risk, risk)
                risk_sum += risk
                risk_n += 1

            scan.findings_count = findings_count
            scan.ports_found = ports_found
            scan.hosts_up = hosts_up
            scan.max_risk_score = max_risk
            scan.avg_risk_score = (risk_sum / risk_n) if risk_n else 0.0
            scan.status = "completed"
            scan.finished_at = utcnow()
            await session.commit()

            await progress_hub.publish(scan_id, _progress_payload(scan))
            logger.info("Scan %s completed in %.1fs: %d hosts, %d ports, %d findings",
                        scan_id, time.monotonic() - started, hosts_up, ports_found, findings_count)

        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            scan = await session.get(ScanJob, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.error_message = str(exc)[:1000]
                scan.finished_at = utcnow()
                await session.commit()
            logger.exception("Scan %s failed: %s", scan_id, exc)
            await progress_hub.publish(scan_id, {
                "scan_id": scan_id, "status": "failed", "error_message": str(exc)[:300],
            })
            raise


def _session_factory():
    from app.core.db import get_session_factory
    return get_session_factory()


def _discovery_backend():
    from app.services.discovery import TcpSweepDiscovery
    return TcpSweepDiscovery()


def _progress_payload(scan: ScanJob) -> dict:
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
