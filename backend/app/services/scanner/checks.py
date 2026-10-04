"""Safe, non-intrusive TCP connectivity checks (pure asyncio/sockets).

We only perform TCP connect() probes and, for a few well-known plaintext
protocols, a polite read of the server's greeting banner. We never send
payloads, never attempt authentication, and never exploit anything.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("app.scanner.checks")

# Ports whose servers send a greeting first; reading it is passive.
_BANNER_PORTS = {21, 22, 25, 110, 143}
_BANNER_READ_BYTES = 256

SERVICE_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "ms-wbt",
    5432: "postgresql",
    5555: "adb",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9092: "kafka",
    9200: "elasticsearch",
    27017: "mongodb",
}


class PortCheckResult:
    __slots__ = ("port", "state", "service_name", "banner", "latency_ms", "error")

    def __init__(self, port: int, state: str, service_name: str | None = None,
                 banner: str | None = None, latency_ms: float | None = None,
                 error: str | None = None):
        self.port = port
        self.state = state  # open | closed | filtered
        self.service_name = service_name
        self.banner = banner
        self.latency_ms = latency_ms
        self.error = error


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


async def check_port(ip: str, port: int, timeout: float | None = None) -> PortCheckResult:
    """Perform a single non-intrusive TCP connect check."""
    timeout = timeout or settings.connect_timeout
    loop = asyncio.get_running_loop()
    start = loop.time()
    banner: str | None = None

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        latency_ms = (loop.time() - start) * 1000.0
        if port in _BANNER_PORTS:
            try:
                data = await asyncio.wait_for(writer.reader.read(_BANNER_READ_BYTES), timeout=0.5)
                banner = data.decode("utf-8", errors="replace").strip()[:512] or None
            except Exception:  # noqa: BLE001 - banner is best-effort only
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return PortCheckResult(port, "open", SERVICE_NAMES.get(port), banner, latency_ms)
    except asyncio.TimeoutError:
        # NOTE: TimeoutError is an OSError subclass since 3.10, so this clause
        # must come BEFORE the OSError clause.
        # On loopback (esp. Windows), a truly closed port typically surfaces as a
        # timeout because the firewall drops rather than rejects, so classify
        # timeouts on loopback as closed; remote timeouts mean filtered.
        state = "closed" if _is_loopback(ip) else "filtered"
        return PortCheckResult(port, state, SERVICE_NAMES.get(port))
    except (ConnectionRefusedError, OSError) as exc:
        latency_ms = (loop.time() - start) * 1000.0
        state = "closed" if isinstance(exc, ConnectionRefusedError) else "filtered"
        return PortCheckResult(port, state, SERVICE_NAMES.get(port), None, latency_ms,
                               error=str(exc) or None)


async def check_host(ip: str, ports: list[int], concurrency: int | None = None) -> list[PortCheckResult]:
    """Check a limited set of ports on one host with bounded concurrency."""
    sem = asyncio.Semaphore(concurrency or settings.scan_concurrency)

    async def _one(p: int) -> PortCheckResult:
        async with sem:
            return await check_port(ip, p)

    return list(await asyncio.gather(*(_one(p) for p in ports)))


async def is_host_alive(ip: str, ports: list[int], concurrency: int | None = None) -> bool:
    """A host is considered alive if any checked port accepts a TCP connection."""
    results = await check_host(ip, ports, concurrency)
    return any(r.state == "open" for r in results)
