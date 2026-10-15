"""
Tests for ML event classification and risk scoring with schema status values.
"""
import pytest

from analysis_engine.ml.event_classifier import EventClassifier
from analysis_engine.ml.features import is_failure, stable_bucket
from analysis_engine.ml.risk_scorer import MLRiskScorer


@pytest.mark.parametrize("status", ["failure", "error", "denied", "failed", "FAILURE"])
def test_is_failure_accepts_schema_values(status):
    assert is_failure({"status": status})


@pytest.mark.parametrize("status", ["success", "", None])
def test_is_failure_rejects_non_failures(status):
    assert not is_failure({"status": status})


def test_stable_bucket_is_deterministic_and_bounded():
    assert stable_bucket("iam.getuser") == stable_bucket("iam.getuser")
    assert 0 <= stable_bucket("anything", buckets=10) < 10


def test_risk_scorer_weights_schema_failures():
    scorer = MLRiskScorer()

    assert scorer.score_event({"status": "failure"}) == pytest.approx(scorer.weights["failed_actions"])
    assert scorer.score_event({"status": "success"}) == 0.0


def test_failed_login_is_medium_risk():
    classifier = EventClassifier()

    result = classifier.classify({"event_type": "auth.login", "action": "ConsoleLogin", "status": "failure"})

    assert result.category == "authentication"
    assert result.risk_level == "medium"
