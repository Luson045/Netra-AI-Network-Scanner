"""Deterministic scope planning, change analysis, prioritization, and verification."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from app.core.errors import ValidationError
from app.models.enums import SEVERITY_ORDER
from app.schemas.pipeline import (
    ClaimVerification,
    EvidenceChange,
    ReviewOrderItem,
    ScanPlan,
)
from app.schemas.scan import ScanCreate
from app.services.scanner.targets import parse_port_spec, parse_targets


def build_scan_plan(source: ScanCreate | str) -> ScanPlan:
    """Parse a request or explicit plain-text scope into a validated scan plan."""
    request = source if isinstance(source, ScanCreate) else _scan_request_from_text(source)
    target_spec = re.sub(r"\s+", ",", request.targets.strip())
    networks, hosts = parse_targets(target_spec)
    ports = parse_port_spec(request.ports)
    return ScanPlan(
        name=request.name,
        target_spec=target_spec,
        port_spec=request.ports,
        targets=networks,
        host_ips=[str(host) for host in hosts],
        ports=ports,
        check_count=len(hosts) * len(ports),
    )


def _scan_request_from_text(text: str) -> ScanCreate:
    if not text.strip():
        raise ValidationError("Scan plan text is empty")

    targets: list[str] = []
    ports: list[str] = []
    names: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^(targets?|scope|ports?|name)\s*[:=]\s*(.*)$", line, re.IGNORECASE)
        if not match:
            targets.append(line)
            continue
        key, value = match.groups()
        key = key.lower()
        if key in {"target", "targets", "scope"}:
            targets.append(value)
        elif key in {"port", "ports"}:
            ports.append(value)
        else:
            names.append(value)

    target_spec = ",".join(targets)
    if not target_spec.strip():
        raise ValidationError("Scan plan text must include targets")
    return ScanCreate(
        name=" ".join(names).strip() or None,
        targets=target_spec,
        ports=",".join(ports) if ports else None,
    )


def compare_observations(
    current: Iterable[Mapping],
    historical: Mapping[str, Mapping],
) -> list[EvidenceChange]:
    """Compare measured port and host states with each host's prior observation."""
    changes: list[EvidenceChange] = []
    for observation in current:
        ip = str(observation["ip"])
        previous = historical.get(ip)
        current_scan_id = int(observation["scan_id"])
        checks = observation["port_checks"]
        current_states = {int(check["port"]): str(check["state"]) for check in checks}
        current_open = {port for port, state in current_states.items() if state == "open"}

        if previous is None:
            changes.append(
                EvidenceChange(
                    ip=ip,
                    change="baseline",
                    current_scan_id=current_scan_id,
                    evidence=(
                        "First retained observation for this host; open ports: "
                        f"{', '.join(map(str, sorted(current_open))) or 'none'}."
                    ),
                )
            )
            continue

        previous_checks = previous["port_checks"]
        previous_states = {
            int(check["port"]): str(check["state"]) for check in previous_checks
        }
        previous_scan_id = int(previous["scan_id"])

        if bool(previous["host_alive"]) != bool(observation["host_alive"]):
            changes.append(
                EvidenceChange(
                    ip=ip,
                    change="host_reachable" if observation["host_alive"] else "host_unreachable",
                    previous_state="reachable" if previous["host_alive"] else "unreachable",
                    current_state="reachable" if observation["host_alive"] else "unreachable",
                    previous_scan_id=previous_scan_id,
                    current_scan_id=current_scan_id,
                    evidence="Host reachability changed between completed scans.",
                )
            )

        comparable_ports = set(previous["ports_scanned"]) & set(observation["ports_scanned"])
        for port in sorted(comparable_ports):
            old_state = previous_states.get(port, "not_observed")
            new_state = current_states.get(port, "not_observed")
            if old_state == new_state:
                continue
            changes.append(
                EvidenceChange(
                    ip=ip,
                    change="port_opened" if new_state == "open" else "port_no_longer_open",
                    port=port,
                    previous_state=old_state,
                    current_state=new_state,
                    previous_scan_id=previous_scan_id,
                    current_scan_id=current_scan_id,
                    evidence=f"TCP/{port} changed from {old_state} to {new_state}.",
                )
            )
    return changes


def prioritize_findings(
    findings: Iterable[Mapping], asset_ips: Mapping[int, str], risk_scores: Mapping[int, int]
) -> list[ReviewOrderItem]:
    """Grade and rank findings using severity first, then measured asset risk."""
    sorted_findings = sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER.get(str(finding["severity"]).lower(), -1),
            -risk_scores.get(finding.get("asset_id"), 0),
            asset_ips.get(finding.get("asset_id"), ""),
            str(finding["rule_id"]),
        ),
    )
    return [
        ReviewOrderItem(
            rank=rank,
            finding_id=int(finding["id"]),
            asset_ip=asset_ips.get(finding.get("asset_id")),
            title=str(finding["title"]),
            severity=str(finding["severity"]),
            risk_score=risk_scores.get(finding.get("asset_id"), 0),
            priority_grade=str(finding["severity"]).upper(),
        )
        for rank, finding in enumerate(sorted_findings, start=1)
    ]


def verify_claims(
    findings: Iterable[Mapping], observations: Mapping[str, Mapping]
) -> list[ClaimVerification]:
    """Check each deterministic finding rule against raw measured port states."""
    verifications: list[ClaimVerification] = []
    for finding in findings:
        ip = str(finding.get("asset_ip") or "")
        observation = observations.get(ip)
        checks = observation["port_checks"] if observation is not None else []
        open_ports = sorted(
            int(check["port"]) for check in checks if check["state"] == "open"
        )
        rule_id = str(finding["rule_id"])
        verified, reason = _verify_rule_claim(rule_id, str(finding["title"]), open_ports)
        if observation is None:
            verified = False
            reason = "No raw host observation was recorded for this finding."
        verifications.append(
            ClaimVerification(
                finding_id=int(finding["id"]),
                rule_id=rule_id,
                claim=str(finding["title"]),
                verified=verified,
                observed_open_ports=open_ports,
                reason=reason,
            )
        )
    return verifications


def _verify_rule_claim(rule_id: str, title: str, open_ports: list[int]) -> tuple[bool, str]:
    sensitive_port = re.fullmatch(r"sensitive-port-(\d+)", rule_id)
    if sensitive_port:
        port = int(sensitive_port.group(1))
        valid = port in open_ports and f"TCP/{port}" in title
        return valid, (
            f"TCP/{port} was observed open." if valid
            else f"TCP/{port} was not observed open in the raw checks."
        )

    if rule_id == "wide-attack-surface":
        stated_count = re.match(r"(\d+)\s+open ports", title)
        measured_count = len(open_ports)
        valid = measured_count >= 8 and stated_count is not None and int(
            stated_count.group(1)
        ) == measured_count
        return valid, (
            f"Measured {measured_count} open ports."
            if valid
            else f"Claimed count did not match {measured_count} measured open ports."
        )

    if rule_id == "legacy-cleartext-remote-access":
        expected = set()
        if "FTP" in title:
            expected.add(21)
        if "Telnet" in title:
            expected.add(23)
        measured = set(open_ports) & {21, 23}
        valid = bool(expected) and expected == measured
        return valid, (
            f"Observed legacy cleartext ports: {', '.join(map(str, sorted(measured))) or 'none'}."
        )

    return False, "No raw-observation verifier is defined for this finding rule."
