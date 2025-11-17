"""User Behavior Analytics (UBA) engine."""
from typing import Dict, Any, List
from dataclasses import dataclass
from collections import Counter

@dataclass
class UserBehaviorProfile:
    """User behavior profile for UBA."""
    user_id: str
    risk_score: float
    anomaly_count: int
    behaviors: Dict[str, int]
    
class UBAEngine:
    """User Behavior Analytics engine combining ML and baselines."""
    
    def __init__(self, anomaly_detector=None, behavioral_baseline=None):
        self.anomaly_detector = anomaly_detector
        self.behavioral_baseline = behavioral_baseline
        self.user_profiles = {}
    
    def analyze_user_behavior(self, events: List[Dict[str, Any]], user_key: str = 'principal') -> Dict[str, UserBehaviorProfile]:
        """Analyze user behavior and build profiles."""
        user_events = {}
        for event in events:
            user = event.get(user_key, 'unknown')
            if user not in user_events:
                user_events[user] = []
            user_events[user].append(event)
        
        profiles = {}
        for user, user_event_list in user_events.items():
            anomaly_count = 0
            risk_scores = []
            
            # Get anomaly detections if available
            if self.anomaly_detector:
                results = self.anomaly_detector.predict(user_event_list)
                anomaly_count = sum(1 for r in results if r.is_anomaly)
                risk_scores = [r.anomaly_score for r in results]
            
            # Calculate overall risk
            risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
            
            # Analyze behaviors
            behaviors = Counter()
            for event in user_event_list:
                behaviors[event.get('event_type', 'unknown')] += 1
            
            profiles[user] = UserBehaviorProfile(
                user_id=user,
                risk_score=risk_score,
                anomaly_count=anomaly_count,
                behaviors=dict(behaviors)
            )
        
        self.user_profiles = profiles
        return profiles
    
    def get_high_risk_users(self, threshold: float = 0.7) -> List[UserBehaviorProfile]:
        """Get users with high risk scores."""
        return [
            profile for profile in self.user_profiles.values()
            if profile.risk_score >= threshold
        ]
