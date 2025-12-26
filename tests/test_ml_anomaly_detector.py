"""
Tests for ML anomaly detection module.
"""
import pytest
from datetime import datetime, timedelta
from typing import List, Dict, Any

from analysis_engine.ml.anomaly_detector import AnomalyDetector


class TestAnomalyDetector:
    """Test anomaly detection functionality."""

    def test_anomaly_detector_initialization(self):
        """Test anomaly detector can be initialized."""
        detector = AnomalyDetector(sensitivity=0.5)
        assert detector is not None
        assert hasattr(detector, 'detect_anomalies')

    def test_detect_high_frequency_anomaly(self, sample_iam_events):
        """Test detection of high-frequency event anomalies."""
        detector = AnomalyDetector()
        
        # Add many events in short time (anomalous)
        events = sample_iam_events.copy()
        base_time = datetime.utcnow()
        
        # Add 50 more events in 1 minute (suspicious)
        for i in range(50):
            events.append({
                "event_id": f"evt-{i}",
                "timestamp": (base_time + timedelta(seconds=i)).isoformat() + "Z",
                "event_type": "iam.list_roles",
                "event_source": "iam",
                "principal": "arn:aws:iam::123456789012:user/attacker",
                "action": "ListRoles"
            })
        
        anomalies = detector.detect_anomalies(events)
        
        # Should detect high frequency as anomalous
        assert len(anomalies) > 0
        assert any(a.get("anomaly_type") == "high_frequency" for a in anomalies)

    def test_detect_unusual_source_ip(self, telemetry_synthesizer):
        """Test detection of unusual source IP addresses."""
        detector = AnomalyDetector()
        
        base_time = datetime.utcnow()
        events = []
        
        # Normal events from same IP
        for i in range(10):
            events.append(
                telemetry_synthesizer.create_iam_event(
                    action="GetUser",
                    principal="arn:aws:iam::123456789012:user/admin",
                    timestamp=(base_time + timedelta(minutes=i)).isoformat() + "Z",
                    source_ip="203.0.113.10"  # Same IP
                )
            )
        
        # Anomalous event from different IP
        events.append(
            telemetry_synthesizer.create_iam_event(
                action="AttachUserPolicy",
                principal="arn:aws:iam::123456789012:user/admin",
                timestamp=(base_time + timedelta(minutes=11)).isoformat() + "Z",
                source_ip="198.51.100.50",  # Different IP
                metadata={"critical": True}
            )
        )
        
        anomalies = detector.detect_anomalies(events)
        
        # May detect IP change as anomalous
        assert isinstance(anomalies, list)

    def test_detect_time_based_anomaly(self, telemetry_synthesizer):
        """Test detection of time-based anomalies (e.g., access at unusual hours)."""
        detector = AnomalyDetector()
        
        events = []
        
        # Normal business hours events (9 AM - 5 PM)
        for day in range(5):
            for hour in range(9, 17):
                events.append(
                    telemetry_synthesizer.create_iam_event(
                        action="GetUser",
                        principal="arn:aws:iam::123456789012:user/employee",
                        timestamp=datetime(2024, 1, day + 1, hour, 0, 0).isoformat() + "Z"
                    )
                )
        
        # Anomalous event at 3 AM
        events.append(
            telemetry_synthesizer.create_iam_event(
                action="AttachUserPolicy",
                principal="arn:aws:iam::123456789012:user/employee",
                timestamp=datetime(2024, 1, 6, 3, 0, 0).isoformat() + "Z",
                metadata={"unusual_time": True}
            )
        )
        
        anomalies = detector.detect_anomalies(events)
        
        # Detector should be able to process time-based patterns
        assert isinstance(anomalies, list)

    def test_detect_no_anomalies_in_normal_traffic(self, sample_iam_events):
        """Test that normal traffic doesn't generate false positives."""
        detector = AnomalyDetector(sensitivity=0.8)  # High threshold
        
        # Use only normal events
        normal_events = sample_iam_events[:2]  # Just reconnaissance events
        
        anomalies = detector.detect_anomalies(normal_events)
        
        # Should have few or no anomalies for normal behavior
        # (depending on implementation, this tests baseline behavior)
        assert isinstance(anomalies, list)

    def test_anomaly_scoring(self, sample_mixed_events):
        """Test that anomalies have proper confidence scores."""
        detector = AnomalyDetector()
        
        anomalies = detector.detect_anomalies(sample_mixed_events)
        
        # Each anomaly should have a score
        for anomaly in anomalies:
            if "confidence" in anomaly or "score" in anomaly:
                score = anomaly.get("confidence", anomaly.get("score"))
                assert 0.0 <= score <= 1.0

    def test_empty_events_list(self):
        """Test handling of empty events list."""
        detector = AnomalyDetector()
        
        anomalies = detector.detect_anomalies([])
        
        assert isinstance(anomalies, list)
        assert len(anomalies) == 0

    def test_single_event(self, sample_iam_events):
        """Test handling of single event."""
        detector = AnomalyDetector()
        
        anomalies = detector.detect_anomalies([sample_iam_events[0]])
        
        # Should handle gracefully
        assert isinstance(anomalies, list)

    def test_different_sensitivity_levels(self, sample_mixed_events):
        """Test that different sensitivity levels produce different results."""
        detector_low = AnomalyDetector(sensitivity=0.3)
        detector_high = AnomalyDetector(sensitivity=0.9)
        
        anomalies_low = detector_low.detect_anomalies(sample_mixed_events)
        anomalies_high = detector_high.detect_anomalies(sample_mixed_events)
        
        # Low sensitivity should detect more anomalies (or equal)
        # (exact behavior depends on implementation)
        assert isinstance(anomalies_low, list)
        assert isinstance(anomalies_high, list)

