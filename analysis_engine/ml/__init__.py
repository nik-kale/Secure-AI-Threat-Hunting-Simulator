"""
Machine Learning module for anomaly detection and behavioral analytics.

v3.0 Features:
- Anomaly detection with Isolation Forest
- Behavioral baseline learning
- Auto-classification of events
- Risk score ML enhancement
- User Behavior Analytics (UBA)
"""
from .anomaly_detector import AnomalyDetector, AnomalyResult
from .behavioral_baseline import BehavioralBaseline, BaselineProfile
from .event_classifier import EventClassifier, ClassificationResult
from .risk_scorer import MLRiskScorer
from .uba_engine import UBAEngine, UserBehaviorProfile

__all__ = [
    'AnomalyDetector',
    'AnomalyResult',
    'BehavioralBaseline',
    'BaselineProfile',
    'EventClassifier',
    'ClassificationResult',
    'MLRiskScorer',
    'UBAEngine',
    'UserBehaviorProfile',
]
