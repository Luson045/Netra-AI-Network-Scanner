"""Finding REST routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.errors import NotFoundError
from app.models import Asset, Finding
from app.models.enums import FindingStatus
from app.schemas.finding import FindingOut
from app.services.explanations import generate_local_ai_explanation

router = APIRouter(tags=["findings"])


@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    scan_id: int | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    q = select(Finding).order_by(Finding.created_at.desc())
    if scan_id is not None:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if status:
        q = q.where(Finding.status == status)
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: int, db: AsyncSession = Depends(get_db)):
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError("Finding not found")
    return finding


@router.post("/findings/{finding_id}/explanation")
async def explain_finding_with_local_ai(
    finding_id: int, db: AsyncSession = Depends(get_db)
):
    """Generate an on-demand explanation using the configured local Ollama model."""
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError("Finding not found")
    asset = await db.get(Asset, finding.asset_id) if finding.asset_id is not None else None
    explanation, model = await generate_local_ai_explanation(
        {
            "title": finding.title,
            "severity": finding.severity,
            "description": finding.description,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
            "asset_ip": asset.ip if asset else None,
            "asset_risk_score": asset.risk_score if asset else None,
        }
    )
    return {"mode": "ai", "provider": "ollama", "model": model, "explanation": explanation}


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def update_finding_status(finding_id: int, status: str = Query(...), db: AsyncSession = Depends(get_db)):
    if status not in (FindingStatus.OPEN, FindingStatus.RESOLVED):
        from app.core.errors import ValidationError
        raise ValidationError("status must be 'open' or 'resolved'")
    finding = await db.get(Finding, finding_id)
    if finding is None:
        from app.core.errors import NotFoundError
        raise NotFoundError("Finding not found")
    finding.status = status
    await db.commit()
    await db.refresh(finding)
    return finding
