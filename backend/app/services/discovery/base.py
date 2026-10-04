"""Discovery backend interface."""

from __future__ import annotations

from typing import Protocol


class DiscoveryBackend(Protocol):
    """A pluggable, authorized discovery method.

    Implementations must only probe targets that have already passed the
    authorization guardrails in app.services.scanner.targets.
    """

    name: str

    async def discover(
        self, hosts: list, ports: list[int], concurrency: int | None = None
    ) -> dict[str, bool]:
        """Return {ip: alive} for the given hosts."""
        ...
