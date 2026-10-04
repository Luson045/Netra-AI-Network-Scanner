"""Target parsing and authorization guardrails.

Accepts input like "127.0.0.1, 192.168.1.0/30, localhost" and produces normalized
network strings, concrete host IPs, and the port list. Public targets are denied
by default: NetGuard only scans networks the user owns or is authorized to assess.
"""

from __future__ import annotations

import ipaddress
import socket

from app.core.config import settings
from app.core.errors import TargetNotAuthorizedError, ValidationError

DEFAULT_PORTS = [
    21, 22, 25, 53, 80, 110, 123, 143, 443, 445,
    3306, 3389, 5432, 6379, 8080, 8443, 9092, 9200,
]

# Ranges considered user-owned by default (defensive use on your own network).
_DEFAULT_AUTHORIZED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def _max_hosts() -> int:
    return settings.max_hosts_per_scan


def _max_ports() -> int:
    return settings.max_ports_per_scan


def parse_port_spec(port_spec: str | None) -> list[int]:
    """Parse '80,443,8000-8100' into a sorted unique list of ports."""
    if not port_spec or not port_spec.strip():
        return list(DEFAULT_PORTS)
    ports: set[int] = set()
    for chunk in port_spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise ValidationError(f"Invalid port range: {chunk!r}") from None
            if not (1 <= start <= end <= 65535):
                raise ValidationError(f"Port range out of bounds: {chunk!r}")
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(chunk)
            except ValueError:
                raise ValidationError(f"Invalid port: {chunk!r}") from None
            if not (1 <= p <= 65535):
                raise ValidationError(f"Port out of bounds: {p}")
            ports.add(p)
    if len(ports) > _max_ports():
        raise ValidationError(f"Too many ports requested ({len(ports)}); max is {_max_ports()}")
    return sorted(ports)


def _resolve_hostname(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _is_authorized(ip) -> bool:
    if settings.allow_localhost and ip.is_loopback:
        return True
    if settings.allow_private_targets:
        for net in _DEFAULT_AUTHORIZED_NETS:
            if ip in net:
                return True
    for cidr in settings.target_allowlist_list:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def parse_targets(target_spec: str) -> tuple[list[str], list]:
    """Parse and authorize the target spec. Returns (network_strings, host_ips)."""
    if not target_spec or not target_spec.strip():
        raise ValidationError("Target specification is empty")

    networks: list[str] = []
    hosts: list = []
    seen: set[str] = set()

    for raw in target_spec.replace("\n", ",").split(","):
        token = raw.strip()
        if not token:
            continue

        if "/" in token:  # CIDR
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                raise ValidationError(f"Invalid CIDR: {token!r}") from None
            if net.num_addresses > _max_hosts():
                raise ValidationError(
                    f"CIDR {token!r} expands to {net.num_addresses} addresses; max is {_max_hosts()}"
                )
            iter_hosts = net.hosts() if net.num_addresses > 2 else [net.network_address]
            for ip in iter_hosts:
                if str(ip) not in seen:
                    seen.add(str(ip))
                    hosts.append(ip)
            networks.append(str(net))
            continue

        try:  # single IP
            ip = ipaddress.ip_address(token)
        except ValueError:
            ip = None
        if ip is not None:
            if str(ip) not in seen:
                seen.add(str(ip))
                hosts.append(ip)
                networks.append(str(ip))
            continue

        resolved = _resolve_hostname(token)  # hostname: resolve for authorization
        if resolved is None:
            raise ValidationError(f"Cannot resolve host: {token!r}")
        try:
            rip = ipaddress.ip_address(resolved)
        except ValueError:
            raise ValidationError(f"Resolved host {token!r} to unparseable address") from None
        if str(rip) not in seen:
            seen.add(str(rip))
            hosts.append(rip)
            networks.append(f"{token} ({resolved})")

    if not hosts:
        raise ValidationError("No valid targets after parsing")
    if len(hosts) > _max_hosts():
        raise ValidationError(f"Too many hosts ({len(hosts)}); max is {_max_hosts()}")

    unauthorized = [h for h in hosts if not _is_authorized(h)]
    if unauthorized:
        sample = ", ".join(str(h) for h in unauthorized[:5])
        raise TargetNotAuthorizedError(
            f"The following targets are outside the authorized scope: {sample}. "
            "NetGuard only scans networks you own or are explicitly authorized to assess "
            "(configure TARGET_ALLOWLIST for other ranges)."
        )

    return networks, hosts
