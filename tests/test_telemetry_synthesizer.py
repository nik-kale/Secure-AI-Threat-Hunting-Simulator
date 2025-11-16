"""
Tests for telemetry synthesizer.
"""
import sys
from pathlib import Path
import json
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.telemetry_synthesizer import TelemetrySynthesizer
from generator.utils.time_utils import get_scenario_timeframe


class TestTelemetrySynthesizer:
    """Test telemetry generation."""

    def test_create_base_event(self):
        """Test basic event creation."""
        synth = TelemetrySynthesizer()

        event = synth.create_base_event(
            event_type="test.event",
            event_source="test",
            timestamp="2025-01-01T00:00:00Z"
        )

        assert event["event_type"] == "test.event"
        assert event["event_source"] == "test"
        assert event["timestamp"] == "2025-01-01T00:00:00Z"
        assert "event_id" in event
        assert event["account_id"] == "123456789012"

    def test_create_iam_event(self):
        """Test IAM event generation."""
        synth = TelemetrySynthesizer()

        event = synth.create_iam_event(
            action="ListRoles",
            principal="arn:aws:iam::123456789012:user/test",
            timestamp="2025-01-01T00:00:00Z",
            status="success"
        )

        assert event["event_type"] == "iam.listroles"
        assert event["action"] == "ListRoles"
        assert event["principal"] == "arn:aws:iam::123456789012:user/test"
        assert event["status"] == "success"
        assert "source_ip" in event
        assert "user_agent" in event

    def test_create_s3_event(self):
        """Test S3 event generation."""
        synth = TelemetrySynthesizer()

        event = synth.create_s3_event(
            action="GetObject",
            principal="arn:aws:iam::123456789012:user/test",
            bucket="test-bucket",
            key="test.txt",
            timestamp="2025-01-01T00:00:00Z"
        )

        assert event["event_type"] == "s3.getobject"
        assert event["action"] == "GetObject"
        assert "test-bucket" in event["resource"]
        assert "bucketName" in event["request_parameters"]

    def test_add_benign_noise(self):
        """Test adding benign background events."""
        synth = TelemetrySynthesizer()

        # Create some attack events
        attack_events = [
            synth.create_iam_event(
                action="ListRoles",
                principal="arn:aws:iam::123456789012:user/attacker",
                timestamp="2025-01-01T00:00:00Z"
            )
            for _ in range(10)
        ]

        # Add noise
        all_events = synth.add_benign_noise(attack_events, noise_ratio=0.3)

        # Should have ~13 events (10 attack + 3 noise)
        assert len(all_events) >= 10
        assert len(all_events) <= 15

        # Events should be sorted by timestamp
        timestamps = [e["timestamp"] for e in all_events]
        assert timestamps == sorted(timestamps)


class TestTimeUtils:
    """Test time utilities."""

    def test_get_scenario_timeframe(self):
        """Test scenario timeframe generation."""
        from generator.utils.time_utils import get_scenario_timeframe

        start_time, end_time = get_scenario_timeframe(duration_hours=1.0, days_ago=1)

        duration_hours = (end_time - start_time).total_seconds() / 3600
        assert abs(duration_hours - 1.0) < 0.01  # Within tolerance


class TestIdUtils:
    """Test ID utilities."""

    def test_generate_ip_address(self):
        """Test IP generation."""
        from generator.utils.id_utils import generate_ip_address

        # Private IP
        private_ip = generate_ip_address(private=True)
        assert private_ip.startswith(("10.", "172.", "192.168."))

        # Public IP
        public_ip = generate_ip_address(private=False)
        assert isinstance(public_ip, str)
        parts = public_ip.split(".")
        assert len(parts) == 4

    def test_generate_arn(self):
        """Test ARN generation."""
        from generator.utils.id_utils import generate_arn

        arn = generate_arn(
            service="iam",
            resource_type="role",
            resource_id="TestRole"
        )

        assert arn.startswith("arn:aws:iam::")
        assert "role/TestRole" in arn


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
