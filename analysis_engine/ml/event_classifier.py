"""Event classifier using ML for automatic event categorization."""
from typing import List, Dict, Any
from dataclasses import dataclass
from collections import Counter
import logging

logger = logging.getLogger(__name__)

@dataclass
class ClassificationResult:
    """Result of event classification."""
    category: str  # 'authentication', 'authorization', 'data_access', 'configuration', 'network'
    confidence: float
    sub_category: str
    risk_level: str  # 'low', 'medium', 'high', 'critical'

class EventClassifier:
    """ML-based event classifier for automatic categorization."""
    
    def __init__(self):
        self.categories = {
            'authentication': ['login', 'logout', 'auth', 'credential', 'password'],
            'authorization': ['assume', 'grant', 'revoke', 'permission', 'role', 'policy'],
            'data_access': ['read', 'get', 'list', 'download', 'access', 's3', 'storage'],
            'configuration': ['create', 'update', 'delete', 'modify', 'configure'],
            'network': ['connect', 'network', 'flow', 'traffic', 'ip', 'port']
        }
    
    def classify(self, event: Dict[str, Any]) -> ClassificationResult:
        """Classify a single event."""
        event_type = event.get('event_type', '').lower()
        action = event.get('action', '').lower()
        text = f"{event_type} {action}"
        
        scores = {}
        for category, keywords in self.categories.items():
            score = sum(1 for kw in keywords if kw in text)
            scores[category] = score
        
        category = max(scores, key=scores.get) if scores else 'unknown'
        confidence = scores.get(category, 0) / max(len(self.categories[category]), 1)
        
        # Determine risk level
        is_suspicious = event.get('metadata', {}).get('suspicious', False)
        is_failed = event.get('status') == 'failed'
        
        if is_suspicious:
            risk_level = 'high'
        elif is_failed and category == 'authentication':
            risk_level = 'medium'
        elif category == 'authorization':
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return ClassificationResult(
            category=category,
            confidence=min(confidence, 1.0),
            sub_category=action or event_type,
            risk_level=risk_level
        )
    
    def batch_classify(self, events: List[Dict[str, Any]]) -> List[ClassificationResult]:
        """Classify multiple events."""
        return [self.classify(event) for event in events]
