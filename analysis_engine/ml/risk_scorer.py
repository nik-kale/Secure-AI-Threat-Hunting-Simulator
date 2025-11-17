"""ML-enhanced risk scoring."""
from typing import Dict, Any, List

class MLRiskScorer:
    """ML-enhanced risk score calculation."""
    
    def __init__(self, base_weights: Dict[str, float] = None):
        self.weights = base_weights or {
            'mitre_techniques': 0.3,
            'failed_actions': 0.2,
            'unusual_time': 0.15,
            'rare_action': 0.15,
            'new_resource': 0.1,
            'anomaly_score': 0.1
        }
    
    def score_event(self, event: Dict[str, Any], anomaly_score: float = 0.0) -> float:
        """Calculate ML-enhanced risk score for event."""
        score = 0.0
        
        # MITRE techniques present
        techniques = event.get('metadata', {}).get('mitre_techniques', [])
        if techniques:
            score += self.weights['mitre_techniques'] * min(len(techniques) / 5.0, 1.0)
        
        # Failed actions
        if event.get('status') == 'failed':
            score += self.weights['failed_actions']
        
        # Anomaly score from ML model
        score += self.weights['anomaly_score'] * anomaly_score
        
        # Suspicious metadata
        if event.get('metadata', {}).get('suspicious'):
            score += 0.2
        
        return min(score, 1.0)
    
    def score_session(self, events: List[Dict[str, Any]], anomaly_scores: List[float] = None) -> float:
        """Calculate session-level risk score."""
        if not events:
            return 0.0
        
        if anomaly_scores is None:
            anomaly_scores = [0.0] * len(events)
        
        event_scores = [
            self.score_event(event, anomaly)
            for event, anomaly in zip(events, anomaly_scores)
        ]
        
        # Weighted average with recency bias
        weights = [1.0 + (i / len(event_scores)) * 0.5 for i in range(len(event_scores))]
        weighted_score = sum(s * w for s, w in zip(event_scores, weights)) / sum(weights)
        
        return min(weighted_score, 1.0)
