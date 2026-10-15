"""
Tests for telemetry parsing and normalisation.
"""
from datetime import datetime

from analysis_engine.core.correlation import EventCorrelator
from analysis_engine.core.parser import EventParser


def _raw(event_id, timestamp):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": "iam.getuser",
        "event_source": "iam",
        "principal": "arn:aws:iam::123456789012:user/alice",
        "action": "GetUser",
        "status": "success",
    }


class TestParseTimestamp:
    def test_offset_timestamps_become_naive_utc(self):
        parsed = EventParser.parse_timestamp("2025-01-01T02:00:00+02:00")

        assert parsed == datetime(2025, 1, 1, 0, 0, 0)
        assert parsed.tzinfo is None

    def test_z_and_offset_forms_are_comparable(self):
        z_form = EventParser.parse_timestamp("2025-01-01T00:00:00Z")
        offset_form = EventParser.parse_timestamp("2025-01-01T00:00:00.500000+00:00")

        assert z_form < offset_form


class TestMixedTimestampCorrelation:
    def test_correlating_mixed_timestamp_formats_does_not_crash(self):
        """Telemetry mixing `Z` and `+00:00` timestamps used to raise TypeError."""
        events = EventParser.parse_events([
            _raw("e1", "2025-01-01T00:00:00Z"),
            _raw("e2", "2025-01-01T00:01:00.250000+00:00"),
            _raw("e3", "2025-01-01T00:02:00Z"),
        ])

        sessions = EventCorrelator(min_events_for_session=3).correlate_multi_criteria(events)

        assert sum(len(s.events) for s in sessions) == 3
