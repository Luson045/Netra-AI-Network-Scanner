"""Raw per-host scan observations and persisted pipeline results."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.scan import utcnow


class ScanObservation(Base):
    __tablename__ = "scan_observations"
    __table_args__ = (
        UniqueConstraint("scan_id", "ip", name="uq_scan_observation_scan_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    host_alive: Mapped[bool] = mapped_column(default=False)
    ports_scanned: Mapped[list[int]] = mapped_column(JSON, default=list)
    port_checks: Mapped[list[dict]] = mapped_column(JSON, default=list)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanPipelineRun(Base):
    __tablename__ = "scan_pipeline_runs"

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_changes: Mapped[list[dict]] = mapped_column(JSON, default=list)
    review_order: Mapped[list[dict]] = mapped_column(JSON, default=list)
    verifications: Mapped[list[dict]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
