"""Risk scoring for assets (0-100)."""

from __future__ import annotations

from app.models.enums import SEVERITY_ORDER

_SEVERITY_WEIGHT = {"info": 2, "low": 5, "medium": 12, "high": 25, "critical": 40}


def compute_asset_risk(findings: list[dict], open_ports: list[dict]) -> int:
    """Compute 0-100 risk for one asset from its findings and open ports."""
    score = 0
    for f in findings:
        score += _SEVERITY_WEIGHT.get(f.get("severity", "info"), 2)
    # A little extra for raw exposure
    score += min(len(open_ports), 10)  # up to +10 for number of open ports
    return max(0, min(100, score))
