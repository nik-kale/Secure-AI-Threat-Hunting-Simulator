"""Automated threat hunting query engine."""
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class HuntQuery:
    """Threat hunting query."""
    name: str
    description: str
    query: str
    format: str  # 'sigma', 'kql', 'spl'
    mitre_techniques: List[str]

@dataclass
class HuntResult:
    """Hunt query result."""
    query_name: str
    matches: List[Dict[str, Any]]
    match_count: int
    confidence: float

class HuntQueryEngine:
    """Automated threat hunting engine."""

    def __init__(self):
        self.queries = self._load_default_queries()

    def _load_default_queries(self) -> List[HuntQuery]:
        """Load default hunt queries."""
        return [
            HuntQuery(
                name="Privilege Escalation",
                description="Hunt for IAM privilege escalation attempts",
                query="event_type:iam.assume_role AND action:PassRole",
                format="sigma",
                mitre_techniques=["T1078", "T1548"]
            ),
            HuntQuery(
                name="Data Exfiltration",
                description="Hunt for suspicious data access",
                query="event_type:s3.get_object AND status:success",
                format="sigma",
                mitre_techniques=["T1530", "T1537"]
            ),
            HuntQuery(
                name="Lateral Movement",
                description="Hunt for lateral movement patterns",
                query="event_type:iam.assume_role AND cross_account:true",
                format="sigma",
                mitre_techniques=["T1078"]
            )
        ]

    def hunt(self, events: List[Dict[str, Any]], query: HuntQuery) -> HuntResult:
        """Execute hunt query."""
        matches = []

        # Simple keyword matching (production would use proper query parsing)
        keywords = query.query.lower().split()

        for event in events:
            event_str = str(event).lower()
            if any(kw.split(':')[1] if ':' in kw else kw in event_str for kw in keywords):
                matches.append(event)

        confidence = min(len(matches) / max(len(events), 1), 1.0)

        return HuntResult(
            query_name=query.name,
            matches=matches,
            match_count=len(matches),
            confidence=confidence
        )

    def hunt_all(self, events: List[Dict[str, Any]]) -> List[HuntResult]:
        """Execute all hunt queries."""
        return [self.hunt(events, query) for query in self.queries]
