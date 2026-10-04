"""Request and response contracts for agent-assisted Deep Scans."""

from pydantic import BaseModel, Field, StrictInt

from app.schemas.scan import ScanOut


class DeepScanCreate(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    targets: str = Field(..., min_length=1, description="Authorized IPs, CIDRs, or hostnames")


class DeepScanApproval(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    targets: str = Field(..., min_length=1)
    ports: list[StrictInt] = Field(..., min_length=1, max_length=24)
    rationale: str = Field(..., min_length=1, max_length=800)


class DeepFindingPriority(BaseModel):
    finding_id: StrictInt
    rationale: str = Field(..., min_length=1, max_length=500)


class DeepScanAnalysis(BaseModel):
    summary: str = Field(..., min_length=1, max_length=1200)
    history_summary: str = Field(..., min_length=1, max_length=900)
    ranked_findings: list[DeepFindingPriority] = Field(default_factory=list, max_length=20)
    recommendations: list[str] = Field(default_factory=list, max_length=8)


class DeepScanQueued(BaseModel):
    scan: ScanOut
    plan: dict


class DeepScanResult(BaseModel):
    scan_id: int
    plan: dict
    analysis: DeepScanAnalysis | None = None
    model: str
    analyzed_at: str | None = None
