"""Tests for analysis rules and risk scoring."""

from app.services.analysis.rules import run_analysis_rules
from app.services.analysis.risk import compute_asset_risk


def _ports(*nums):
    return [{"port": p, "service": None, "banner": None} for p in nums]


def test_no_findings_for_clean_host():
    findings = run_analysis_rules("10.0.0.5", _ports(8080))
    assert findings == []


def test_sensitive_port_emits_finding():
    findings = run_analysis_rules("10.0.0.5", _ports(6379))
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "sensitive-port-6379"
    assert f["severity"] == "high"
    assert "Redis" in f["title"]


def test_legacy_cleartext_rule():
    findings = run_analysis_rules("10.0.0.5", _ports(23))
    rule_ids = [f["rule_id"] for f in findings]
    assert "legacy-cleartext-remote-access" in rule_ids


def test_wide_surface_rule():
    findings = run_analysis_rules("10.0.0.5", _ports(*range(1, 12)))
    assert any(f["rule_id"] == "wide-attack-surface" for f in findings)


def test_risk_score_bounds():
    low = compute_asset_risk([], _ports(8080))
    high = compute_asset_risk(
        [{"severity": "critical"}] * 3, _ports(*range(1, 15))
    )
    assert 0 <= low <= 100
    assert 0 <= high <= 100
    assert high > low
