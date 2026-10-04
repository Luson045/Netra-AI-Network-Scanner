"""Enum string values stored in the database (plain strings for easy querying)."""


class ScanStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


ACTIVE_SCAN_STATUSES = {ScanStatus.PENDING, ScanStatus.RUNNING}


class FindingSeverity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


class FindingStatus:
    OPEN = "open"
    RESOLVED = "resolved"


class ServiceState:
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
