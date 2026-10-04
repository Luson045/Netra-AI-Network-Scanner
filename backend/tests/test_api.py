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
