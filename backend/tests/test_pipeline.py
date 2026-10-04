"""Tests for scope planning and deterministic pipeline analysis."""

from app.services.pipeline import (
    build_scan_plan,
    compare_observations,
    prioritize_findings,
    verify_claims,
)
from app.schemas.scan import ScanCreate


def test_scope_planner_parses_plain_text_and_request():
    plan = build_scan_plan(
        "name: office\n targets: 127.0.0.1, localhost\nports: 443,80"
    )
    assert plan.name == "office"
    assert plan.host_ips == ["127.0.0.1"]
    assert plan.ports == [80, 443]
    assert plan.check_count == 2

    request_plan = build_scan_plan(ScanCreate(targets="127.0.0.1", ports="22"))
    assert request_plan.host_ips == ["127.0.0.1"]
    assert request_plan.ports == [22]


def test_change_analysis_compares_only_shared_scanned_ports():
    changes = compare_observations(
        [
            {
                "scan_id": 2,
                "ip": "127.0.0.1",
                "host_alive": True,
                "ports_scanned": [22, 80, 443],
                "port_checks": [
                    {"port": 22, "state": "open"},
                    {"port": 80, "state": "closed"},
                    {"port": 443, "state": "open"},
                ],
            }
        ],
        {
            "127.0.0.1": {
                "scan_id": 1,
                "host_alive": True,
                "ports_scanned": [22, 80, 8080],
                "port_checks": [
                    {"port": 22, "state": "open"},
                    {"port": 80, "state": "open"},
                    {"port": 8080, "state": "open"},
                ],
            }
        },
    )
    assert [(change.change, change.port) for change in changes] == [
        ("port_no_longer_open", 80)
    ]


def test_review_order_ranks_severity_then_risk():
    order = prioritize_findings(
        [
            {"id": 1, "asset_id": 10, "rule_id": "a", "title": "Medium", "severity": "medium"},
            {"id": 2, "asset_id": 11, "rule_id": "b", "title": "High", "severity": "high"},
        ],
        {10: "127.0.0.1", 11: "127.0.0.2"},
        {10: 95, 11: 30},
    )
    assert [item.finding_id for item in order] == [2, 1]
    assert [item.rank for item in order] == [1, 2]


def test_verifier_checks_finding_claims_against_raw_metrics():
    findings = [
        {
            "id": 1,
            "asset_ip": "127.0.0.1",
            "rule_id": "sensitive-port-6379",
            "title": "Redis exposed on TCP/6379",
        },
        {
            "id": 2,
            "asset_ip": "127.0.0.1",
            "rule_id": "sensitive-port-22",
            "title": "SSH exposed on TCP/22",
        },
    ]
    verification = verify_claims(
        findings,
        {
            "127.0.0.1": {
                "port_checks": [
                    {"port": 6379, "state": "open"},
                    {"port": 22, "state": "closed"},
                ]
            }
        },
    )
    assert [item.verified for item in verification] == [True, False]
