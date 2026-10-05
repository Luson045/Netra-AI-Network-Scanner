"""API smoke tests using in-memory SQLite via the FastAPI TestClient."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    from app.core.config import get_settings

    get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_create_scan_rejects_public_target(client):
    r = client.post("/scans", json={"targets": "8.8.8.8"})
    assert r.status_code == 403
    body = r.json()
    assert body["error"]["code"] == "target_not_authorized"


def test_scan_preview_validates_scope_without_queuing(client):
    r = client.post(
        "/scans/preview",
        json={"targets": "127.0.0.1", "ports": "22,8000"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "targets": ["127.0.0.1"],
        "host_count": 1,
        "ports": [22, 8000],
        "check_count": 2,
    }
    assert client.get("/scans").json() == []


def test_plan_endpoint_accepts_plain_text_or_scan_request(client):
    plain_text = client.post(
        "/scans/plan",
        json={"scan": "targets: 127.0.0.1\nports: 80,443"},
    )
    assert plain_text.status_code == 200
    assert plain_text.json()["host_ips"] == ["127.0.0.1"]
    assert plain_text.json()["ports"] == [80, 443]
    assert plain_text.json()["check_count"] == 2

    request = client.post(
        "/scans/plan",
        json={"scan": {"targets": "127.0.0.1", "ports": "22"}},
    )
    assert request.status_code == 200
    assert request.json()["ports"] == [22]


def test_scan_preview_rejects_unauthorized_scope_and_bad_ports(client):
    unauthorized = client.post(
        "/scans/preview",
        json={"targets": "8.8.8.8", "ports": "80"},
    )
    assert unauthorized.status_code == 403

    invalid_ports = client.post(
        "/scans",
        json={"targets": "127.0.0.1", "ports": "not-a-port"},
    )
    assert invalid_ports.status_code == 422


def test_create_scan_and_poll_progress(client):
    r = client.post("/scans", json={"targets": "127.0.0.1", "name": "unit-test"})
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "pending"
    assert scan["port_spec"] is None
    assert scan["name"] == "unit-test"
    assert client.get("/scans").json()[0]["name"] == "unit-test"

    # progress endpoint (worker isn't running, so it stays pending)
    r = client.get(f"/scans/{scan['id']}/progress")
    assert r.status_code == 200
    assert r.json()["scan_id"] == scan["id"]
    assert r.json()["status"] == "pending"

    # cancel it
    r = client.post(f"/scans/{scan['id']}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"

    # double cancel -> 409
    r = client.post(f"/scans/{scan['id']}/cancel")
    assert r.status_code == 409


def test_create_scan_invalid_targets(client):
    r = client.post("/scans", json={"targets": ""})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_error"


def test_list_scans_and_history(client):
    client.post("/scans", json={"targets": "127.0.0.1"})
    r = client.get("/scans")
    assert r.status_code == 200
    assert len(r.json()) >= 1

    r = client.get("/scans/history")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_stats_endpoints_empty(client):
    for path in ("/stats/overview", "/stats/severities", "/stats/top-ports", "/stats/anomalies"):
        r = client.get(path)
        assert r.status_code == 200, path


def test_get_missing_scan_404(client):
    r = client.get("/scans/99999")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


def test_explanation_for_missing_finding_returns_404(client):
    response = client.post("/findings/99999/explanation")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_deep_scan_plans_ports_with_agent_then_requires_approval(client, monkeypatch):
    async def fake_plan(targets, name):
        assert targets == "127.0.0.1"
        assert name == "Agent review"
        return (
            {
                "target_spec": "127.0.0.1",
                "targets": ["127.0.0.1"],
                "host_ips": ["127.0.0.1"],
                "ports": [22, 443, 6379],
                "check_count": 3,
                "rationale": "Check remote access, web service, and key-value store exposure.",
            },
            "test-model",
        )

    monkeypatch.setattr("app.api.routes_scans.create_agent_port_plan", fake_plan)
    existing_ids = {scan["id"] for scan in client.get("/scans").json()}
    plan_response = client.post(
        "/scans/deep/plan",
        json={"name": "Agent review", "targets": "127.0.0.1"},
    )
    assert plan_response.status_code == 200
    assert plan_response.json()["plan"]["ports"] == [22, 443, 6379]
    assert {scan["id"] for scan in client.get("/scans").json()} == existing_ids

    queued = client.post(
        "/scans/deep",
        json={
            "name": "Agent review",
            "targets": "127.0.0.1",
            "ports": [22, 443, 6379],
            "rationale": "A reviewed plan.",
        },
    )
    assert queued.status_code == 201, queued.text
    assert queued.json()["scan"]["deep_scan"] is True
    assert queued.json()["plan"]["ports"] == [22, 443, 6379]
    assert next(
        scan for scan in client.get("/scans").json()
        if scan["id"] == queued.json()["scan"]["id"]
    )["deep_scan"] is True

    rejected = client.post(
        "/scans/deep",
        json={
            "targets": "127.0.0.1",
            "ports": [65535],
            "rationale": "Outside agent list.",
        },
    )
    assert rejected.status_code == 422


def test_deep_scan_approval_accepts_a_port_from_local_listener_context(client, monkeypatch):
    from app.services import deep_agents

    monkeypatch.setattr(
        deep_agents,
        "local_device_profile",
        lambda: {
            "platform": "Windows 11",
            "listeners_available": True,
            "listening_services": [{"port": 5040, "processes": ["Code.exe"]}],
        },
    )
    monkeypatch.setattr(deep_agents.platform, "system", lambda: "Windows")

    approved = client.post(
        "/scans/deep",
        json={
            "targets": "127.0.0.1",
            "ports": [5040],
            "rationale": "Check a service listening on the scanner device.",
        },
    )

    assert approved.status_code == 201, approved.text
    assert approved.json()["plan"]["ports"] == [5040]


def test_deep_scan_without_findings_skips_local_analysis(client, monkeypatch):
    from app.core.db import get_session_factory
    from app.models import DeepScanRun, ScanJob, ScanPipelineRun
    from app.services import deep_agents

    queued = client.post(
        "/scans", json={"name": "No risk scan", "targets": "127.0.0.1"}
    ).json()

    async def seed_completed_deep_scan():
        async with get_session_factory()() as db:
            scan = await db.get(ScanJob, queued["id"])
            scan.status = "completed"
            db.add(DeepScanRun(scan_id=scan.id, plan={"ports": [80]}, model="test-model"))
            db.add(ScanPipelineRun(
                scan_id=scan.id,
                evidence_changes=[],
                review_order=[],
                verifications=[],
            ))
            await db.commit()

    client.portal.call(seed_completed_deep_scan)

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("AI analysis should be skipped when no findings exist")

    monkeypatch.setattr(deep_agents, "generate_local_text", fail_if_called)
    result = client.post(f"/scans/{queued['id']}/deep-analysis")

    assert result.status_code == 200, result.text
    assert result.json()["analysis"]["summary"] == "Everything is OK!"
    assert result.json()["model"] == "No AI analysis needed"


def test_delete_scan_history_keeps_active_jobs_and_supports_single_delete(client):
    existing = client.get("/scans").json()
    existing_active = {
        scan["id"] for scan in existing if scan["status"] in {"pending", "running"}
    }
    existing_terminal = {
        scan["id"] for scan in existing if scan["status"] not in {"pending", "running"}
    }
    completed_history = client.post("/scans", json={"targets": "127.0.0.1"}).json()
    assert client.post(f"/scans/{completed_history['id']}/cancel").status_code == 200
    active_scan = client.post("/scans", json={"targets": "127.0.0.1"}).json()

    deleted = client.delete("/scans")
    assert deleted.status_code == 200
    assert deleted.json() == {
        "deleted_count": len(existing_terminal) + 1,
        "retained_active_count": len(existing_active) + 1,
    }
    assert {scan["id"] for scan in client.get("/scans").json()} == existing_active | {
        active_scan["id"]
    }
    assert client.delete(f"/scans/{active_scan['id']}").status_code == 409

    assert client.post(f"/scans/{active_scan['id']}/cancel").status_code == 200
    assert client.delete(f"/scans/{active_scan['id']}").status_code == 204
    for scan_id in existing_active:
        assert client.post(f"/scans/{scan_id}/cancel").status_code == 200
        assert client.delete(f"/scans/{scan_id}").status_code == 204
    assert client.get("/scans").json() == []


def test_deleting_scan_history_rebuilds_assets_services_and_findings(client):
    from app.core.db import get_session_factory
    from app.models import Asset, Finding, ScanJob, ScanObservation, Service

    retained = client.post("/scans", json={"targets": "127.0.0.1"}).json()
    removed = client.post("/scans", json={"targets": "127.0.0.1"}).json()

    async def seed_history():
        async with get_session_factory()() as db:
            retained_scan = await db.get(ScanJob, retained["id"])
            removed_scan = await db.get(ScanJob, removed["id"])
            retained_scan.status = "cancelled"
            removed_scan.status = "cancelled"
            asset = Asset(ip="127.0.0.1", is_alive=True, risk_score=25)
            db.add(asset)
            await db.flush()
            db.add_all([
                Service(asset_id=asset.id, port=22, service_name="ssh", state="open"),
                Finding(
                    scan_id=retained["id"],
                    asset_id=asset.id,
                    rule_id="retained-rule",
                    title="Retained finding",
                    severity="low",
                    description="Retained evidence.",
                    recommendation="Keep it.",
                ),
                Finding(
                    scan_id=removed["id"],
                    asset_id=asset.id,
                    rule_id="removed-rule",
                    title="Removed finding",
                    severity="low",
                    description="Deleted with history.",
                    recommendation="Remove it.",
                ),
                ScanObservation(
                    scan_id=retained["id"],
                    ip="127.0.0.1",
                    host_alive=True,
                    ports_scanned=[22],
                    port_checks=[{"port": 22, "state": "open", "service": "ssh"}],
                ),
                ScanObservation(
                    scan_id=removed["id"],
                    ip="127.0.0.1",
                    host_alive=False,
                    ports_scanned=[22],
                    port_checks=[{"port": 22, "state": "closed"}],
                ),
            ])
            await db.commit()

    client.portal.call(seed_history)

    assert client.delete(f"/scans/{removed['id']}").status_code == 204
    assert len(client.get("/assets").json()) == 1
    assert len(client.get("/services").json()) == 1
    remaining_findings = client.get(f"/findings?scan_id={retained['id']}").json()
    assert [finding["title"] for finding in remaining_findings] == ["Retained finding"]

    active_scan = client.post("/scans", json={"targets": "127.0.0.1"}).json()
    asset_id = client.get("/assets").json()[0]["id"]

    async def add_active_scan_results():
        async with get_session_factory()() as db:
            db.add_all([
                Finding(
                    scan_id=active_scan["id"],
                    asset_id=asset_id,
                    rule_id="active-rule",
                    title="Active scan finding",
                    severity="low",
                    description="Current finding.",
                    recommendation="Remove it with history.",
                ),
                ScanObservation(
                    scan_id=active_scan["id"],
                    ip="127.0.0.1",
                    host_alive=True,
                    ports_scanned=[22],
                    port_checks=[{"port": 22, "state": "open", "service": "ssh"}],
                ),
            ])
            await db.commit()

    client.portal.call(add_active_scan_results)
    assert client.get("/findings").json()

    deleted = client.delete("/scans")
    assert deleted.status_code == 200
    assert deleted.json()["retained_active_count"] == 1
    assert [scan["id"] for scan in client.get("/scans").json()] == [active_scan["id"]]
    assert client.get("/assets").json() == []
    assert client.get("/services").json() == []
    assert client.get("/findings").json() == []
