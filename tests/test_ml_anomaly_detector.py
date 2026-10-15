"""
Tests for ML anomaly detection module.
"""

import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from analysis_engine.ml.anomaly_detector import AnomalyDetector, AnomalyResult

REPO_ROOT = Path(__file__).resolve().parent.parent


def _event(
    minute,
    action="GetUser",
    status="success",
    principal="arn:aws:iam::123456789012:user/alice",
):
    return {
        "timestamp": (datetime(2025, 1, 6, 10, 0) + timedelta(minutes=minute)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "event_type": f"iam.{action.lower()}",
        "action": action,
        "status": status,
        "principal": principal,
        "resource": "arn:aws:iam::123456789012:user/alice",
        "source_ip": "203.0.113.10",
        "metadata": {},
    }


def _baseline(n=40):
    return [_event(i) for i in range(n)]


class TestAnomalyDetector:
    def test_empty_events_list(self):
        assert AnomalyDetector().predict([]) == []

    def test_fit_requires_ten_events(self):
        detector = AnomalyDetector().fit(_baseline(5))

        assert detector.is_fitted is False

    def test_fit_and_predict_returns_one_result_per_event(self, sample_mixed_events):
        detector = AnomalyDetector(n_estimators=20).fit(_baseline())

        results = detector.predict(sample_mixed_events)

        assert detector.is_fitted is True
        assert len(results) == len(sample_mixed_events)
        for result in results:
            assert isinstance(result, AnomalyResult)
            assert 0.0 <= result.anomaly_score <= 1.0
            assert 0.0 <= result.confidence <= 1.0
            assert result.severity in {"low", "medium", "high", "critical"}

    def test_batch_predict_filters_on_threshold(self):
        # Unfitted, so the statistical fallback scores both events: without a
        # baseline every event is rare (0.7); the suspicious marker adds 0.5.
        detector = AnomalyDetector()
        events = [_event(1), dict(_event(2), metadata={"suspicious": True})]

        anomalous, results = detector.batch_predict(events, threshold=0.75)

        assert len(results) == 2
        assert anomalous == [events[1]]


class TestFailureStatus:
    """The telemetry schema spells failures "failure", "error" or "denied"."""

    def test_schema_failure_status_is_encoded_as_failure(self):
        detector = AnomalyDetector()

        features = detector.extract_features(
            [_event(1, status="failure"), _event(2, status="denied")]
        )

        status_column = detector.feature_names.index("status_code")
        assert list(features[:, status_column]) == [-1.0, -1.0]

    def test_statistical_fallback_counts_schema_failures(self):
        detector = AnomalyDetector()

        result = detector.predict([_event(1, status="failure")])[0]

        assert "failed_action" in result.explanation


class TestStableFeatures:
    def test_features_are_identical_across_processes(self):
        """Hash-randomised features made a fitted model meaningless in another process."""
        code = (
            "from analysis_engine.ml.anomaly_detector import AnomalyDetector;"
            "e={'event_type':'iam.getuser','action':'GetUser','principal':'p','resource':'r'};"
            "print(AnomalyDetector().extract_features([e]).tolist())"
        )
        outputs = {
            subprocess.run(
                [sys.executable, "-c", code],
                cwd=REPO_ROOT,
                env=dict(os.environ, PYTHONHASHSEED=seed),
                capture_output=True,
                text=True,
                check=True,
            )
            .stdout.strip()
            .splitlines()[-1]
            for seed in ("1", "2")
        }

        assert len(outputs) == 1

    def test_feature_matrix_shape(self):
        detector = AnomalyDetector()

        features = detector.extract_features(_baseline(3))

        assert isinstance(features, np.ndarray)
        assert features.shape == (3, len(detector.feature_names))
