"""Asset & service REST routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.errors import NotFoundError
from app.models import Asset, Service
from app.schemas.asset import AssetOut, ServiceOut

router = APIRouter(tags=["assets"])


def _asset_out(asset: Asset, services: list[Service]) -> AssetOut:
    return AssetOut(
        id=asset.id,
        ip=asset.ip,
        hostname=asset.hostname,
        os_guess=asset.os_guess,
        mac_address=asset.mac_address,
        is_alive=asset.is_alive,
        first_seen=asset.first_seen,
        last_seen=asset.last_seen,
        risk_score=asset.risk_score,
        services=[
            ServiceOut(
                id=s.id,
                asset_id=s.asset_id,
                port=s.port,
                protocol=s.protocol,
                state=s.state,
                service_name=s.service_name,
                banner=s.banner,
                first_seen=s.first_seen,
                last_seen=s.last_seen,
            )
            for s in services
        ],
    )


async def _services_for(db: AsyncSession, asset_id: int) -> list[Service]:
    result = await db.execute(
        select(Service).where(Service.asset_id == asset_id).order_by(Service.port)
    )
    return list(result.scalars().all())


@router.get("/assets", response_model=list[AssetOut])
async def list_assets(
    alive_only: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    q = select(Asset).order_by(Asset.last_seen.desc())
    if alive_only:
        q = q.where(Asset.is_alive.is_(True))
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    assets = result.scalars().all()
    return [_asset_out(a, await _services_for(db, a.id)) for a in assets]


@router.get("/assets/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: int, db: AsyncSession = Depends(get_db)):
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    return _asset_out(asset, await _services_for(db, asset.id))


@router.get("/services", response_model=list[ServiceOut])
async def list_services(
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Service).order_by(Service.last_seen.desc()).offset(offset).limit(limit)
    )
    return result.scalars().all()
