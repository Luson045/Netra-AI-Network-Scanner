"""Dashboard stats schemas."""

from pydantic import BaseModel


class OverviewStats(BaseModel):
    total_assets: int
    alive_assets: int
    total_services: int
    open_findings: int
    high_or_critical_findings: int
    scans_24h: int
    max_risk_score: int
    avg_risk_score: float


class SeverityCount(BaseModel):
    severity: str
    count: int


class TopOpenPort(BaseModel):
    port: int
    service_name: str | None
    count: int


class AnomalyPoint(BaseModel):
    """Baseline-deviation point for the risk/anomaly chart."""

    scan_id: int
    created_at: str
    hosts_up: int
    ports_found: int
    findings_count: int
    port_delta_vs_baseline: int  # +N new ports vs personal baseline, -N if fewer
    is_anomaly: bool
    z_score: float
