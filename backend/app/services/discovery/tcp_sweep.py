"""Default discovery backend: TCP connect sweep over the common port set."""

from __future__ import annotations

import asyncio

from app.core.config import settings
from app.services.scanner.checks import check_host


class TcpSweepDiscovery:
    name = "tcp-sweep"

    async def discover(
        self, hosts: list, ports: list[int], concurrency: int | None = None
    ) -> dict[str, bool]:
        sem = asyncio.Semaphore(concurrency or settings.scan_concurrency)
        results: dict[str, bool] = {}

        async def _one(ip: str) -> None:
            async with sem:
                alive = any(r.state == "open" for r in await check_host(ip, ports))
            results[ip] = alive

        await asyncio.gather(*(_one(str(h)) for h in hosts))
        return results
