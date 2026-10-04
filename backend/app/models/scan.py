"""ScanJob ORM model."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(
        String(200), default="Unnamed scan", server_default="Unnamed scan", nullable=False
    )
    target_spec: Mapped[str] = mapped_column(String(512))  # original user input
    port_spec: Mapped[str | None] = mapped_column(String(256), nullable=True)  # e.g. "22,80,8000-8100"
    targets: Mapped[str] = mapped_column(Text)             # expanded, one CIDR/IP per line
    total_targets: Mapped[int] = mapped_column(Integer, default=0)
    completed_targets: Mapped[int] = mapped_column(Integer, default=0)
    hosts_up: Mapped[int] = mapped_column(Integer, default=0)
    ports_found: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    max_risk_score: Mapped[int] = mapped_column(Integer, default=0)
    avg_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), index=True, default="pending")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
