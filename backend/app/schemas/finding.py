"""Pydantic schemas for Findings."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    asset_id: int | None
    rule_id: str
    title: str
    severity: str
    description: str
    recommendation: str
    evidence: str | None
    status: str
    created_at: datetime
