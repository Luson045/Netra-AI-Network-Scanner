"""Persisted local-agent plans and analysis for Deep Scan jobs."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.scan import utcnow


class DeepScanRun(Base):
    __tablename__ = "deep_scan_runs"

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    plan: Mapped[dict] = mapped_column(JSON)
    analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    model: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
