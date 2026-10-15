"""Feature helpers shared by the ML modules."""
import zlib
from typing import Any, Dict

# Status values the telemetry schema (generator/schemas/telemetry_event_schema.json)
# uses for unsuccessful events, plus the legacy "failed" spelling.
FAILURE_STATUSES = frozenset({"failure", "failed", "error", "denied"})


def is_failure(event: Dict[str, Any]) -> bool:
    """Return True when the event records an unsuccessful action."""
    return str(event.get("status", "")).lower() in FAILURE_STATUSES


def stable_bucket(value: Any, buckets: int = 1000) -> int:
    """
    Map a value to a bucket that is the same in every process.

    The built-in hash() of a string changes between interpreter runs
    (PYTHONHASHSEED), so features built on it are not reproducible.
    """
    return zlib.crc32(str(value).encode("utf-8")) % buckets
