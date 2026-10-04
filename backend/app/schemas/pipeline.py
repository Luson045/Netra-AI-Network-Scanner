"""Schemas for the deterministic scan pipeline."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.scan import ScanCreate


class ScanPlan(BaseModel):
    """Authorized, normalized plan produced before a scan is queued or run."""

    name: str | None
    target_spec: str
    port_spec: str | None
    targets: list[str]
    host_ips: list[str]
    ports: list[int]
    check_count: int


class EvidenceChange(BaseModel):
    ip: str
    change: str
    port: int | None = None
    previous_state: str | None = None
    current_state: str | None = None
    previous_scan_id: int | None = None
    current_scan_id: int
    evidence: str


class ReviewOrderItem(BaseModel):
    rank: int
    finding_id: int
    asset_ip: str | None
    title: str
    severity: str
    risk_score: int
    priority_grade: str


class ClaimVerification(BaseModel):
    finding_id: int
    rule_id: str
    claim: str
    verified: bool
    observed_open_ports: list[int]
    reason: str


class ScanPipelineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: int
    evidence_changes: list[EvidenceChange] = Field(default_factory=list)
    review_order: list[ReviewOrderItem] = Field(default_factory=list)
    verifications: list[ClaimVerification] = Field(default_factory=list)
    created_at: datetime


class ScanPlanInput(BaseModel):
    """JSON wrapper for a plain-text scope or an existing ScanCreate request."""

    scan: ScanCreate | str
