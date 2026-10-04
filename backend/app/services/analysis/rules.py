"""Deterministic analysis rules (defensive observations only)."""

from __future__ import annotations

RULE_SENSITIVE_PORTS: dict[int, dict] = {
    21: {"service": "FTP", "why": "FTP transmits credentials and data in cleartext."},
    23: {"service": "Telnet", "why": "Telnet has no encryption; credentials are exposed on the wire."},
    445: {"service": "SMB", "why": "SMB is frequently targeted by worms and ransomware; limit exposure."},
    3389: {"service": "RDP", "why": "Exposed RDP is a common initial access vector; restrict with VPN/allowlists."},
    6379: {"service": "Redis", "why": "Redis without auth/TLS can allow unauthenticated data access."},
    9200: {"service": "Elasticsearch", "why": "Unprotected Elasticsearch nodes expose stored documents."},
    1433: {"service": "MSSQL", "why": "Database services should not be broadly reachable."},
    3306: {"service": "MySQL", "why": "Database services should not be broadly reachable."},
    5432: {"service": "PostgreSQL", "why": "Database services should not be broadly reachable."},
    27017: {"service": "MongoDB", "why": "NoSQL stores should not be broadly reachable."},
    161: {"service": "SNMP", "why": "SNMP can leak device configuration; use v3 and ACLs."},
}

RULE_DATABASE_PORTS = {1433, 3306, 5432, 6379, 9200, 27017}


def run_analysis_rules(ip: str, open_ports: list[dict]) -> list[dict]:
    """Run all analysis rules for one host. Returns a list of finding dicts.

    open_ports items: {"port": int, "service": str|None, "banner": str|None}
    Findings are deduplicated per (scan, asset, rule_id) by a DB unique constraint;
    rules are written to emit at most one finding per rule per host.
    """
    findings: list[dict] = []
    ports = [p["port"] for p in open_ports]
    port_set = set(ports)

    def _emit(rule_id: str, title: str, severity: str, description: str,
              recommendation: str, evidence: str | None = None) -> None:
        findings.append({
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence,
        })

    # Rule 1: each sensitive open port gets a targeted observation.
    for port, meta in RULE_SENSITIVE_PORTS.items():
        if port not in port_set:
            continue
        svc = next((p.get("service") or meta["service"] for p in open_ports if p["port"] == port), meta["service"])
        banner = next((p.get("banner") for p in open_ports if p["port"] == port), None)
        evidence = f"TCP/{port} ({svc}) accepted a connection from {ip}"
        if banner:
            evidence += f'; server banner: "{banner[:120]}"'
        _emit(
            rule_id=f"sensitive-port-{port}",
            title=f"{meta['service']} exposed on TCP/{port}",
            severity="medium" if port not in RULE_DATABASE_PORTS else "high",
            description=f"{meta['service']} is listening on {ip}:{port}. {meta['why']}",
            recommendation=_recommendation_for(port, svc),
            evidence=evidence,
        )

    # Rule 2: many open ports -> wide attack surface on a single host.
    if len(ports) >= 8:
        _emit(
            rule_id="wide-attack-surface",
            title=f"{len(ports)} open ports on one host",
            severity="medium",
            description=(
                f"{ip} has {len(ports)} reachable services. Large exposed surface "
                "increases the chance that one misconfiguration is reachable."
            ),
            recommendation=(
                "Review which services must be network-reachable. Disable unused ones and "
                "place the rest behind a firewall or VPN."
            ),
            evidence=f"Open ports: {', '.join(str(p) for p in sorted(port_set))}",
        )

    # Rule 3: legacy cleartext remote access.
    legacy = port_set & {21, 23}
    if legacy:
        names = ", ".join("FTP" if p == 21 else "Telnet" for p in sorted(legacy))
        _emit(
            rule_id="legacy-cleartext-remote-access",
            title=f"Legacy cleartext remote-access services ({names})",
            severity="high",
            description=(
                f"{ip} exposes cleartext management protocols ({names}). Any observer on "
                "the path can capture credentials and session content."
            ),
            recommendation="Disable FTP/Telnet; use SFTP/SCP and SSH instead.",
            evidence=f"Open legacy ports: {', '.join(str(p) for p in sorted(legacy))}",
        )

    return findings


def _recommendation_for(port: int, service: str) -> str:
    recs: dict[int, str] = {
        21: "Prefer SFTP/FTPS; if FTP is required, restrict source IPs and require TLS.",
        23: "Disable Telnet and manage the device over SSH.",
        445: "Restrict SMB to required subnets, enforce SMB signing, keep patches current.",
        3389: "Put RDP behind VPN, enable NLA, require MFA, restrict source ranges.",
        161: "Use SNMPv3 with authentication/privacy and ACL the community of allowed queriers.",
        6379: "Enable Redis AUTH and TLS, bind to required interfaces, firewall to app hosts.",
        9200: "Enable Elasticsearch security (auth + TLS), restrict to application networks.",
        3389: "Put RDP behind VPN, enable NLA, require MFA.",
    }
    if port in RULE_DATABASE_PORTS and port not in recs:
        return (
            f"Restrict {service} to application hosts via firewall rules, require strong "
            "authentication and TLS where supported; never expose databases to user networks."
        )
    return recs.get(
        port,
        "Confirm this service must be reachable; restrict access with firewall rules and keep it patched.",
    )
