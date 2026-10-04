"""Pydantic schemas for Assets and Services."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    port: int
    protocol: str
    state: str
    service_name: str | None
    banner: str | None
    first_seen: datetime
    last_seen: datetime


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip: str
    hostname: str | None
    os_guess: str | None
    mac_address: str | None
    is_alive: bool
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    services: list[ServiceOut] = []
