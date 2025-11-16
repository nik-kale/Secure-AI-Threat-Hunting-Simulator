"""
Tests for event correlation.
"""
import sys
from pathlib import Path
from datetime import datetime, timedelta
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis_engine.core.parser import NormalizedEvent
from analysis_engine.core.correlation import EventCorrelator, CorrelationSession


class TestEventCorrelator:
    """Test event correlation."""

    def test_correlate_by_session_id(self):
        """Test correlation by explicit session ID."""
        correlator = EventCorrelator(min_events_for_session=2)

        # Create events with same session ID
        events = [
            NormalizedEvent(
                event_id=f"event-{i}",
                timestamp=datetime(2025, 1, 1, 0, i, 0),
                event_type="test.event",
                event_source="test",
                account_id="123456789012",
                region="us-east-1",
                session_id="session-1",
                principal="arn:aws:iam::123456789012:user/test"
            )
            for i in range(5)
        ]

        sessions = correlator.correlate_by_session_id(events)

        assert len(sessions) == 1
        assert sessions[0].session_id == "session-1"
        assert len(sessions[0].events) == 5

    def test_correlate_by_principal(self):
        """Test correlation by principal."""
        correlator = EventCorrelator(
            time_window_minutes=60,
            min_events_for_session=2
        )

        # Create events from same principal
        events = [
            NormalizedEvent(
                event_id=f"event-{i}",
                timestamp=datetime(2025, 1, 1, 0, i, 0),
                event_type="test.event",
                event_source="test",
                account_id="123456789012",
                region="us-east-1",
                principal="arn:aws:iam::123456789012:user/test"
            )
            for i in range(5)
        ]

        sessions = correlator.correlate_by_principal(events)

        assert len(sessions) >= 1
        assert all("test" in s.session_id for s in sessions)

    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        correlator = EventCorrelator()

        # Create suspicious session
        session = CorrelationSession(session_id="test-session")

        for i in range(10):
            event = NormalizedEvent(
                event_id=f"event-{i}",
                timestamp=datetime(2025, 1, 1, 0, i, 0),
                event_type="iam.create_role",
                event_source="iam",
                account_id="123456789012",
                region="us-east-1",
                metadata={"attack_stage": "persistence"}
            )
            session.add_event(event)

        score = correlator._calculate_risk_score(session)

        # Should have elevated risk score due to attack_stage metadata
        assert score > 0.3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
