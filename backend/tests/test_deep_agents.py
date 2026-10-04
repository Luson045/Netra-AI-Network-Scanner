"""Tests for the constrained local Deep Scan agents."""

import pytest

from app.core.errors import ExplanationServiceError
from app.services import deep_agents


@pytest.mark.asyncio
async def test_deep_planner_uses_only_authorized_targets_and_candidate_ports(monkeypatch):
    device_profile = {
        "platform": "Windows 11",
        "listeners_available": True,
        "listening_services": [{"port": 50000, "processes": ["python.exe"]}],
    }
    monkeypatch.setattr(deep_agents, "local_device_profile", lambda: device_profile)

    async def fake_generate(prompt, *, max_tokens, json_mode):
        assert "Resolved authorized hosts" in prompt
        assert "Windows 11" in prompt
        assert "50000" in prompt
        assert "5985" in prompt
        assert max_tokens == 220
        assert json_mode is True
        return (
            '{"ports":[443,22,50000],"rationale":"Check observed, web, and secure shell ports."}',
            "test-model",
        )

    monkeypatch.setattr(deep_agents, "generate_local_text", fake_generate)
    plan, model = await deep_agents.create_agent_port_plan("127.0.0.1", "Test")

    assert plan["host_ips"] == ["127.0.0.1"]
    assert plan["ports"] == [22, 443, 50000]
    assert plan["check_count"] == 3
    assert plan["device_profile"] == device_profile
    assert model == "test-model"


@pytest.mark.asyncio
async def test_deep_planner_rejects_unapproved_ports(monkeypatch):
    async def fake_generate(prompt, *, max_tokens, json_mode):
        return ('{"ports":[65535],"rationale":"Try everything."}', "test-model")

    monkeypatch.setattr(deep_agents, "generate_local_text", fake_generate)
    with pytest.raises(ExplanationServiceError, match="outside the approved candidate list"):
        await deep_agents.create_agent_port_plan("127.0.0.1", None)


@pytest.mark.asyncio
async def test_deep_analysis_rejects_unknown_finding_ids(monkeypatch):
    async def fake_generate(prompt, *, max_tokens, json_mode):
        return (
            '{"summary":"One service was observed.","history_summary":"Baseline scan.",'
            '"ranked_findings":[{"finding_id":999,"rationale":"Unrelated claim."}],'
            '"recommendations":[]}',
            "test-model",
        )

    monkeypatch.setattr(deep_agents, "generate_local_text", fake_generate)
    pipeline = {
        "review_order": [{"finding_id": 2, "title": "Observed", "severity": "low"}],
        "evidence_changes": [],
        "verifications": [],
    }
    with pytest.raises(ExplanationServiceError, match="referenced findings outside this scan"):
        await deep_agents.analyze_deep_scan({"ports": [80]}, pipeline, "Test")


@pytest.mark.asyncio
async def test_deep_analysis_skips_ai_when_no_findings(monkeypatch):
    async def fail_if_called(*args, **kwargs):
        raise AssertionError("AI analysis should not run when there are no findings")

    monkeypatch.setattr(deep_agents, "generate_local_text", fail_if_called)
    analysis, model = await deep_agents.analyze_deep_scan(
        {"ports": [80]},
        {"review_order": [], "evidence_changes": [], "verifications": []},
        "Test",
    )

    assert analysis["summary"] == "Everything is OK!"
    assert analysis["ranked_findings"] == []
    assert analysis["recommendations"] == []
    assert model == "No AI analysis needed"
