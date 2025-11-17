"""
Anomaly detection using Isolation Forest and statistical methods.

Detects unusual patterns in cloud telemetry events that may indicate
malicious activity or misconfigurations.
"""
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import numpy as np
import logging
from collections import Counter, defaultdict

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available. Anomaly detection will use statistical fallback.")

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""
    is_anomaly: bool
    anomaly_score: float  # -1.0 to 1.0, lower = more anomalous
    confidence: float  # 0.0 to 1.0
    anomaly_type: str  # 'behavioral', 'statistical', 'temporal', 'volumetric'
    explanation: str
    contributing_features: Dict[str, float]
    severity: str  # 'low', 'medium', 'high', 'critical'


class AnomalyDetector:
    """
    Machine learning-based anomaly detector for cloud telemetry.

    Uses Isolation Forest for unsupervised anomaly detection combined
    with statistical methods for robust detection.
    """

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        max_samples: int = 256,
        random_state: int = 42
    ):
        """
        Initialize anomaly detector.

        Args:
            contamination: Expected proportion of anomalies (0.0 to 0.5)
            n_estimators: Number of isolation trees
            max_samples: Samples to draw for each tree
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state

        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                contamination=contamination,
                n_estimators=n_estimators,
                max_samples=max_samples,
                random_state=random_state,
                n_jobs=-1  # Use all CPUs
            )
            self.scaler = StandardScaler()
            self.pca = None  # Optional dimensionality reduction
        else:
            self.model = None
            logger.warning("Using statistical fallback for anomaly detection")

        self.is_fitted = False
        self.feature_names = []
        self.baseline_stats = {}

    def extract_features(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """
        Extract numerical features from events for ML model.

        Args:
            events: List of telemetry events

        Returns:
            Feature matrix (n_events x n_features)
        """
        features = []

        for event in events:
            feature_vector = []

            # Temporal features
            if 'timestamp' in event:
                try:
                    ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    feature_vector.extend([
                        ts.hour,  # Hour of day
                        ts.weekday(),  # Day of week
                        ts.day,  # Day of month
                    ])
                except:
                    feature_vector.extend([0, 0, 0])
            else:
                feature_vector.extend([0, 0, 0])

            # Event type encoding (hash-based)
            event_type = event.get('event_type', '')
            feature_vector.append(hash(event_type) % 1000)

            # Action encoding
            action = event.get('action', '')
            feature_vector.append(hash(action) % 1000)

            # Status encoding
            status = event.get('status', 'unknown')
            status_code = {'success': 1, 'failed': -1, 'unknown': 0}.get(status, 0)
            feature_vector.append(status_code)

            # Principal encoding
            principal = event.get('principal', '')
            feature_vector.append(hash(principal) % 1000)

            # Resource encoding
            resource = event.get('resource', '')
            feature_vector.append(hash(resource) % 1000)

            # Metadata features
            metadata = event.get('metadata', {})
            feature_vector.append(1 if metadata.get('suspicious') else 0)
            feature_vector.append(len(metadata.get('mitre_techniques', [])))

            # IP address features (if present)
            source_ip = event.get('source_ip', '')
            feature_vector.append(len(source_ip.split('.')))  # IP structure

            features.append(feature_vector)

        # Store feature names for interpretation
        if not self.feature_names:
            self.feature_names = [
                'hour', 'weekday', 'day_of_month',
                'event_type_hash', 'action_hash', 'status_code',
                'principal_hash', 'resource_hash',
                'is_suspicious', 'mitre_technique_count', 'ip_structure'
            ]

        return np.array(features, dtype=float)

    def fit(self, events: List[Dict[str, Any]]) -> 'AnomalyDetector':
        """
        Train anomaly detector on baseline events.

        Args:
            events: Training events (normal behavior)

        Returns:
            Self for chaining
        """
        if len(events) < 10:
            logger.warning(f"Insufficient training data: {len(events)} events. Need at least 10.")
            return self

        logger.info(f"Training anomaly detector on {len(events)} events")

        # Extract features
        X = self.extract_features(events)

        if SKLEARN_AVAILABLE and self.model:
            # Scale features
            X_scaled = self.scaler.fit_transform(X)

            # Optional PCA for high-dimensional data
            if X.shape[1] > 20:
                self.pca = PCA(n_components=0.95, random_state=self.random_state)
                X_scaled = self.pca.fit_transform(X_scaled)

            # Train Isolation Forest
            self.model.fit(X_scaled)
            self.is_fitted = True

            logger.info(f"Anomaly detector trained on {X.shape[0]} samples with {X.shape[1]} features")

        # Calculate statistical baseline (works with or without sklearn)
        self._calculate_baseline_stats(events)

        return self

    def _calculate_baseline_stats(self, events: List[Dict[str, Any]]):
        """Calculate statistical baseline for fallback detection."""
        # Event type distribution
        event_types = [e.get('event_type', '') for e in events]
        self.baseline_stats['event_type_freq'] = Counter(event_types)

        # Action distribution
        actions = [e.get('action', '') for e in events]
        self.baseline_stats['action_freq'] = Counter(actions)

        # Principal distribution
        principals = [e.get('principal', '') for e in events]
        self.baseline_stats['principal_freq'] = Counter(principals)

        # Temporal patterns (hourly distribution)
        hours = []
        for event in events:
            if 'timestamp' in event:
                try:
                    ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    hours.append(ts.hour)
                except:
                    pass
        self.baseline_stats['hour_distribution'] = Counter(hours)

        # Average events per principal
        principal_counts = Counter(principals)
        self.baseline_stats['avg_events_per_principal'] = np.mean(list(principal_counts.values())) if principal_counts else 0
        self.baseline_stats['std_events_per_principal'] = np.std(list(principal_counts.values())) if principal_counts else 0

    def predict(self, events: List[Dict[str, Any]]) -> List[AnomalyResult]:
        """
        Detect anomalies in events.

        Args:
            events: Events to analyze

        Returns:
            List of anomaly results for each event
        """
        if not events:
            return []

        # Use ML model if available and fitted
        if SKLEARN_AVAILABLE and self.model and self.is_fitted:
            return self._ml_predict(events)
        else:
            # Fallback to statistical detection
            return self._statistical_predict(events)

    def _ml_predict(self, events: List[Dict[str, Any]]) -> List[AnomalyResult]:
        """ML-based anomaly prediction."""
        X = self.extract_features(events)
        X_scaled = self.scaler.transform(X)

        if self.pca:
            X_scaled = self.pca.transform(X_scaled)

        # Predict anomalies (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(X_scaled)

        # Get anomaly scores
        scores = self.model.score_samples(X_scaled)

        # Normalize scores to 0-1 range (higher = more anomalous)
        scores_normalized = 1 / (1 + np.exp(scores))  # Sigmoid normalization

        results = []
        for i, (event, pred, score) in enumerate(zip(events, predictions, scores_normalized)):
            is_anomaly = pred == -1

            # Determine severity based on score
            if score > 0.9:
                severity = 'critical'
            elif score > 0.75:
                severity = 'high'
            elif score > 0.6:
                severity = 'medium'
            else:
                severity = 'low'

            # Feature importance (simplified)
            feature_vector = X[i]
            contributing_features = {}
            for j, (name, value) in enumerate(zip(self.feature_names, feature_vector)):
                if value != 0:  # Only non-zero features
                    contributing_features[name] = float(value)

            # Determine anomaly type
            anomaly_type = self._determine_anomaly_type(event, feature_vector)

            # Generate explanation
            explanation = self._generate_explanation(event, anomaly_type, score)

            results.append(AnomalyResult(
                is_anomaly=is_anomaly,
                anomaly_score=float(score),
                confidence=min(abs(score - 0.5) * 2, 1.0),  # Distance from decision boundary
                anomaly_type=anomaly_type,
                explanation=explanation,
                contributing_features=contributing_features,
                severity=severity
            ))

        return results

    def _statistical_predict(self, events: List[Dict[str, Any]]) -> List[AnomalyResult]:
        """Statistical fallback anomaly prediction."""
        results = []

        for event in events:
            score = 0.0
            anomalies = []

            # Check event type frequency
            event_type = event.get('event_type', '')
            expected_freq = self.baseline_stats.get('event_type_freq', {}).get(event_type, 0)
            if expected_freq < 2:  # Rare event type
                score += 0.3
                anomalies.append('rare_event_type')

            # Check action frequency
            action = event.get('action', '')
            action_freq = self.baseline_stats.get('action_freq', {}).get(action, 0)
            if action_freq < 2:
                score += 0.2
                anomalies.append('rare_action')

            # Check principal activity
            principal = event.get('principal', '')
            principal_freq = self.baseline_stats.get('principal_freq', {}).get(principal, 0)
            avg_principal = self.baseline_stats.get('avg_events_per_principal', 0)
            std_principal = self.baseline_stats.get('std_events_per_principal', 1)

            if avg_principal > 0 and principal_freq > avg_principal + 2 * std_principal:
                score += 0.3
                anomalies.append('high_volume_principal')

            # Check temporal anomalies
            if 'timestamp' in event:
                try:
                    ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    hour_dist = self.baseline_stats.get('hour_distribution', {})
                    if hour_dist.get(ts.hour, 0) < 2:  # Unusual hour
                        score += 0.2
                        anomalies.append('unusual_time')
                except:
                    pass

            # Check for suspicious metadata
            if event.get('metadata', {}).get('suspicious'):
                score += 0.5
                anomalies.append('marked_suspicious')

            # Failed actions are more suspicious
            if event.get('status') == 'failed':
                score += 0.1
                anomalies.append('failed_action')

            # Normalize score
            score = min(score, 1.0)

            is_anomaly = score > 0.5

            if score > 0.8:
                severity = 'high'
            elif score > 0.6:
                severity = 'medium'
            else:
                severity = 'low'

            anomaly_type = 'statistical'
            if 'high_volume' in str(anomalies):
                anomaly_type = 'volumetric'
            elif 'unusual_time' in str(anomalies):
                anomaly_type = 'temporal'
            elif anomalies:
                anomaly_type = 'behavioral'

            explanation = f"Statistical anomaly detected: {', '.join(anomalies)}" if anomalies else "Normal behavior"

            results.append(AnomalyResult(
                is_anomaly=is_anomaly,
                anomaly_score=score,
                confidence=score if is_anomaly else (1.0 - score),
                anomaly_type=anomaly_type,
                explanation=explanation,
                contributing_features={'score': score},
                severity=severity
            ))

        return results

    def _determine_anomaly_type(self, event: Dict[str, Any], features: np.ndarray) -> str:
        """Determine the type of anomaly based on features."""
        # Check temporal features
        hour, weekday, day = features[0:3]
        if hour < 6 or hour > 22:  # Outside business hours
            return 'temporal'

        # Check if status is failed
        if features[5] == -1:  # status_code for failed
            return 'behavioral'

        # Check if marked suspicious
        if features[8] == 1:
            return 'behavioral'

        # Check MITRE technique count
        if features[9] > 3:
            return 'behavioral'

        return 'statistical'

    def _generate_explanation(self, event: Dict[str, Any], anomaly_type: str, score: float) -> str:
        """Generate human-readable explanation for anomaly."""
        explanations = []

        if score > 0.8:
            explanations.append("Highly unusual pattern detected")
        elif score > 0.6:
            explanations.append("Moderately unusual pattern")
        else:
            explanations.append("Slightly unusual pattern")

        if anomaly_type == 'temporal':
            explanations.append("occurring at unusual time")
        elif anomaly_type == 'behavioral':
            explanations.append("showing abnormal behavior")
        elif anomaly_type == 'volumetric':
            explanations.append("with unusual volume")

        event_type = event.get('event_type', 'unknown')
        principal = event.get('principal', 'unknown')

        explanations.append(f"for event type '{event_type}' by '{principal}'")

        return " ".join(explanations)

    def batch_predict(
        self,
        events: List[Dict[str, Any]],
        threshold: float = 0.6
    ) -> Tuple[List[Dict[str, Any]], List[AnomalyResult]]:
        """
        Batch predict and filter anomalies.

        Args:
            events: Events to analyze
            threshold: Anomaly score threshold

        Returns:
            Tuple of (anomalous_events, all_results)
        """
        results = self.predict(events)

        anomalous_events = [
            event for event, result in zip(events, results)
            if result.is_anomaly and result.anomaly_score >= threshold
        ]

        return anomalous_events, results

    def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance scores.

        Returns:
            Dictionary of feature names to importance scores
        """
        if not self.is_fitted or not SKLEARN_AVAILABLE:
            return {}

        # For Isolation Forest, we can't directly get feature importance
        # But we can estimate based on how often features are used for splits
        # This is a placeholder - real implementation would need tree traversal
        return {name: 1.0 / len(self.feature_names) for name in self.feature_names}
