"""Default discovery backend: TCP connect sweep over the common port set."""

from __future__ import annotations

import asyncio

from app.core.config import settings
from app.services.scanner.checks import PortCheckResult, check_host


class TcpSweepDiscovery:
    name = "tcp-sweep"

    async def observe(
        self, hosts: list, ports: list[int], concurrency: int | None = None
    ) -> dict[str, list[PortCheckResult]]:
        """Return the raw bounded TCP checks used to determine host reachability."""
        sem = asyncio.Semaphore(concurrency or settings.scan_concurrency)
        observations: dict[str, list[PortCheckResult]] = {}

        async def _one(ip: str) -> None:
            async with sem:
                observations[ip] = await check_host(ip, ports)

        await asyncio.gather(*(_one(str(host)) for host in hosts))
        return observations

    async def discover(
        self, hosts: list, ports: list[int], concurrency: int | None = None
    ) -> dict[str, bool]:
        observations = await self.observe(hosts, ports, concurrency)
        return {
            ip: any(result.state == "open" for result in results)
            for ip, results in observations.items()
        }
