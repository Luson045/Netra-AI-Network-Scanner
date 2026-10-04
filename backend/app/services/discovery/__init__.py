"""Discovery backends.

The scanner is modular: additional authorized discovery methods (e.g. mDNS,
ARP neighbour tables, SNMP inventory read-only, cloud provider inventory APIs)
can be plugged in by implementing DiscoveryBackend and registering it below.
"""

from app.services.discovery.base import DiscoveryBackend
from app.services.discovery.tcp_sweep import TcpSweepDiscovery

__all__ = ["DiscoveryBackend", "TcpSweepDiscovery"]
