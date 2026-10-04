"""Pydantic schemas for ScanJob."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    targets: str = Field(
        ...,
        description="Comma/space/newline separated IPs, CIDRs or hostnames, e.g. '127.0.0.1, 192.168.1.0/30'",
    )
    ports: str | None = Field(
        default=None,
        description="Optional port spec, e.g. '22,80,443,8000-8100'. Defaults to a safe common set.",
    )


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    target_spec: str
    port_spec: str | None
    targets: str
    total_targets: int
    completed_targets: int
    hosts_up: int
    ports_found: int
    findings_count: int
    max_risk_score: int
    avg_risk_score: float
    status: str
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ScanProgressOut(BaseModel):
    """Lightweight progress payload for WebSocket / polling."""

    scan_id: int
    status: str
    total_targets: int
    completed_targets: int
    hosts_up: int
    ports_found: int
    findings_count: int
    error_message: str | None
    finished_at: datetime | None


class ScanHistoryPoint(BaseModel):
    """Aggregated point for the history chart."""

    date: str  # ISO date
    scans: int
    hosts_up: int
    findings: int
