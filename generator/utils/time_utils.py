"""
Time utilities for telemetry generation.
"""
from datetime import datetime, timedelta
from typing import Optional
import random


def generate_timestamp(
    base_time: Optional[datetime] = None,
    offset_seconds: float = 0
) -> str:
    """
    Generate an ISO 8601 timestamp.

    Args:
        base_time: Base datetime (defaults to now)
        offset_seconds: Offset in seconds from base time

    Returns:
        ISO 8601 formatted timestamp string
    """
    if base_time is None:
        base_time = datetime.utcnow()

    result_time = base_time + timedelta(seconds=offset_seconds)
    return result_time.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_time_sequence(
    start_time: datetime,
    duration_hours: float,
    num_events: int,
    jitter_seconds: float = 60.0
) -> list[str]:
    """
    Generate a sequence of timestamps with realistic jitter.

    Args:
        start_time: Starting datetime
        duration_hours: Total duration in hours
        num_events: Number of timestamps to generate
        jitter_seconds: Maximum random jitter in seconds

    Returns:
        List of ISO 8601 timestamp strings
    """
    timestamps = []
    duration_seconds = duration_hours * 3600
    interval = duration_seconds / max(num_events - 1, 1)

    for i in range(num_events):
        base_offset = i * interval
        jitter = random.uniform(-jitter_seconds, jitter_seconds)
        offset = max(0, base_offset + jitter)  # Ensure non-negative
        timestamps.append(generate_timestamp(start_time, offset))

    return sorted(timestamps)


def parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse an ISO 8601 timestamp string.

    Args:
        timestamp_str: ISO 8601 formatted string

    Returns:
        datetime object
    """
    return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")


def time_delta_seconds(ts1: str, ts2: str) -> float:
    """
    Calculate the difference in seconds between two timestamps.

    Args:
        ts1: First timestamp (ISO 8601)
        ts2: Second timestamp (ISO 8601)

    Returns:
        Difference in seconds (ts2 - ts1)
    """
    dt1 = parse_timestamp(ts1)
    dt2 = parse_timestamp(ts2)
    return (dt2 - dt1).total_seconds()


def get_scenario_timeframe(
    duration_hours: float = 2.0,
    days_ago: int = 1
) -> tuple[datetime, datetime]:
    """
    Get a realistic timeframe for a scenario.

    Args:
        duration_hours: Scenario duration in hours
        days_ago: How many days in the past to start

    Returns:
        Tuple of (start_time, end_time)
    """
    end_time = datetime.utcnow() - timedelta(days=days_ago)
    start_time = end_time - timedelta(hours=duration_hours)
    return start_time, end_time
