"""End-to-end worker test: claim a pending scan and execute it against localhost."""

import asyncio
import socket

import pytest
from sqlalchemy import select

from app.core.db import session_scope
from app.models import (
    Asset,
    Finding,
    ScanJob,
    ScanObservation,
    ScanPipelineRun,
    Service,
)
from app.schemas.pipeline import ScanPipelineOut
from app.workers.scan_worker import _claim_next_scan, _run_one


@pytest.fixture()
async def open_local_port():
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


async def test_full_scan_flow(monkeypatch, tmp_path, open_local_port):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/worker.db")
    from app.core.config import get_settings

    get_settings.cache_clear()
    from app.core.db import dispose_engine, get_session_factory

    await dispose_engine()

    from app.core.utils import init_db
    await init_db()

    # Create a scan targeting localhost with a small fast port set
    async with session_scope() as session:
        scan = ScanJob(
            name="worker-e2e",
            target_spec="127.0.0.1",
            port_spec=f"{open_local_port},1",
            targets="127.0.0.1",
            status="pending",
        )
        session.add(scan)

    claimed = await _claim_next_scan(get_session_factory())
    assert claimed is not None
    await _run_one(claimed)

    async with session_scope() as session:
        job = await session.get(ScanJob, claimed)
        assert job.status == "completed"
        assert job.hosts_up == 1
        assert job.ports_found >= 1

        assets = (await session.execute(select(Asset))).scalars().all()
        assert len(assets) == 1
        assert assets[0].ip == "127.0.0.1"
        assert assets[0].is_alive is True

        services = (await session.execute(select(Service))).scalars().all()
        assert any(s.port == open_local_port for s in services)

        findings = (await session.execute(select(Finding))).scalars().all()
        # port 1 closed; the ephemeral high port is unknown to rules -> maybe zero findings
        assert isinstance(findings, list)

        observations = (
            await session.execute(select(ScanObservation).where(ScanObservation.scan_id == claimed))
        ).scalars().all()
        assert len(observations) == 1
        assert open_local_port in [
            check["port"] for check in observations[0].port_checks
            if check["state"] == "open"
        ]

        pipeline = await session.get(ScanPipelineRun, claimed)
        assert pipeline is not None
        assert pipeline.evidence_changes[0]["change"] == "baseline"
        assert isinstance(pipeline.review_order, list)
        assert isinstance(pipeline.verifications, list)
        assert ScanPipelineOut.model_validate(pipeline).scan_id == claimed

    await dispose_engine()
