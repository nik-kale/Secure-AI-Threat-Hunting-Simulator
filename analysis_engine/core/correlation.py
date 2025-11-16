"""
Event correlation engine.
"""
from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, List, Set
from dataclasses import dataclass, field
import logging

from .parser import NormalizedEvent

logger = logging.getLogger(__name__)


@dataclass
class CorrelationSession:
    """Represents a correlated session of events."""

    session_id: str
    events: List[NormalizedEvent] = field(default_factory=list)
    principals: Set[str] = field(default_factory=set)
    source_ips: Set[str] = field(default_factory=set)
    resources: Set[str] = field(default_factory=set)
    event_types: Set[str] = field(default_factory=set)

    start_time: Any = None  # datetime
    end_time: Any = None

    attack_stages: Set[str] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)

    risk_score: float = 0.0
    is_malicious: bool = False

    def add_event(self, event: NormalizedEvent) -> None:
        """Add an event to this session."""
        self.events.append(event)

        if event.principal:
            self.principals.add(event.principal)
        if event.source_ip:
            self.source_ips.add(event.source_ip)
        if event.resource:
            self.resources.add(event.resource)
        self.event_types.add(event.event_type)

        # Update time range
        if self.start_time is None or event.timestamp < self.start_time:
            self.start_time = event.timestamp
        if self.end_time is None or event.timestamp > self.end_time:
            self.end_time = event.timestamp

        # Extract attack metadata
        if event.metadata.get("attack_stage"):
            self.attack_stages.add(event.metadata["attack_stage"])
        if event.metadata.get("mitre_technique"):
            self.mitre_techniques.add(event.metadata["mitre_technique"])

    def duration_seconds(self) -> float:
        """Calculate session duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "num_events": len(self.events),
            "principals": list(self.principals),
            "source_ips": list(self.source_ips),
            "resources": list(self.resources),
            "event_types": list(self.event_types),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds(),
            "attack_stages": list(self.attack_stages),
            "mitre_techniques": list(self.mitre_techniques),
            "risk_score": self.risk_score,
            "is_malicious": self.is_malicious,
        }


class EventCorrelator:
    """Correlates events into sessions based on various criteria."""

    def __init__(
        self,
        time_window_minutes: int = 60,
        min_events_for_session: int = 3
    ):
        """
        Initialize correlator.

        Args:
            time_window_minutes: Time window for correlating events
            min_events_for_session: Minimum events to form a session
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self.min_events = min_events_for_session

    def correlate_by_session_id(
        self,
        events: List[NormalizedEvent]
    ) -> List[CorrelationSession]:
        """
        Correlate events by explicit session ID.

        Args:
            events: List of normalized events

        Returns:
            List of correlation sessions
        """
        sessions_dict: Dict[str, CorrelationSession] = {}

        for event in events:
            if not event.session_id:
                continue

            if event.session_id not in sessions_dict:
                sessions_dict[event.session_id] = CorrelationSession(
                    session_id=event.session_id
                )

            sessions_dict[event.session_id].add_event(event)

        # Filter by minimum events
        sessions = [
            s for s in sessions_dict.values()
            if len(s.events) >= self.min_events
        ]

        logger.info(f"Correlated {len(sessions)} sessions by session ID")
        return sessions

    def correlate_by_principal(
        self,
        events: List[NormalizedEvent]
    ) -> List[CorrelationSession]:
        """
        Correlate events by principal (user/role) within time window.

        Args:
            events: List of normalized events

        Returns:
            List of correlation sessions
        """
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        principal_sessions: Dict[str, List[CorrelationSession]] = defaultdict(list)

        for event in sorted_events:
            if not event.principal:
                continue

            # Find or create session for this principal
            placed = False

            for session in principal_sessions[event.principal]:
                # Check if event fits within time window of existing session
                if session.end_time and (event.timestamp - session.end_time) <= self.time_window:
                    session.add_event(event)
                    placed = True
                    break

            if not placed:
                # Create new session
                new_session = CorrelationSession(
                    session_id=f"principal-{event.principal}-{len(principal_sessions[event.principal])}"
                )
                new_session.add_event(event)
                principal_sessions[event.principal].append(new_session)

        # Flatten and filter
        all_sessions = [
            s for sessions in principal_sessions.values()
            for s in sessions
            if len(s.events) >= self.min_events
        ]

        logger.info(f"Correlated {len(all_sessions)} sessions by principal")
        return all_sessions

    def correlate_by_source_ip(
        self,
        events: List[NormalizedEvent]
    ) -> List[CorrelationSession]:
        """
        Correlate events by source IP within time window.

        Args:
            events: List of normalized events

        Returns:
            List of correlation sessions
        """
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        ip_sessions: Dict[str, List[CorrelationSession]] = defaultdict(list)

        for event in sorted_events:
            if not event.source_ip:
                continue

            placed = False

            for session in ip_sessions[event.source_ip]:
                if session.end_time and (event.timestamp - session.end_time) <= self.time_window:
                    session.add_event(event)
                    placed = True
                    break

            if not placed:
                new_session = CorrelationSession(
                    session_id=f"ip-{event.source_ip}-{len(ip_sessions[event.source_ip])}"
                )
                new_session.add_event(event)
                ip_sessions[event.source_ip].append(new_session)

        all_sessions = [
            s for sessions in ip_sessions.values()
            for s in sessions
            if len(s.events) >= self.min_events
        ]

        logger.info(f"Correlated {len(all_sessions)} sessions by source IP")
        return all_sessions

    def correlate_multi_criteria(
        self,
        events: List[NormalizedEvent]
    ) -> List[CorrelationSession]:
        """
        Correlate using multiple criteria (session ID, principal, IP).

        Args:
            events: List of normalized events

        Returns:
            Combined list of correlation sessions
        """
        # Try session ID first (most reliable)
        session_id_sessions = self.correlate_by_session_id(events)

        # Get events not already in a session
        events_in_sessions = set()
        for session in session_id_sessions:
            for event in session.events:
                events_in_sessions.add(event.event_id)

        remaining_events = [
            e for e in events
            if e.event_id not in events_in_sessions
        ]

        # Correlate remaining by principal
        principal_sessions = self.correlate_by_principal(remaining_events)

        # Combine all sessions
        all_sessions = session_id_sessions + principal_sessions

        logger.info(f"Total correlated sessions: {len(all_sessions)}")
        return all_sessions

    def identify_suspicious_sessions(
        self,
        sessions: List[CorrelationSession],
        threshold: float = 0.5
    ) -> List[CorrelationSession]:
        """
        Identify potentially suspicious sessions based on heuristics.

        Args:
            sessions: List of correlation sessions
            threshold: Risk score threshold

        Returns:
            List of suspicious sessions
        """
        suspicious = []

        for session in sessions:
            risk_score = self._calculate_risk_score(session)
            session.risk_score = risk_score

            if risk_score >= threshold:
                session.is_malicious = True
                suspicious.append(session)

        logger.info(f"Identified {len(suspicious)} suspicious sessions")
        return suspicious

    def _calculate_risk_score(self, session: CorrelationSession) -> float:
        """Calculate risk score for a session (0.0 to 1.0)."""
        score = 0.0

        # Check for attack stage metadata
        if session.attack_stages:
            score += 0.4

        # High event volume
        if len(session.events) > 20:
            score += 0.2

        # Multiple failure events
        failure_count = sum(1 for e in session.events if e.status in ["failure", "denied", "error"])
        if failure_count > 5:
            score += 0.2

        # Check for suspicious event types
        suspicious_types = ["iam.create_role", "iam.attach_policy", "lambda.create_function"]
        if any(et in session.event_types for et in suspicious_types):
            score += 0.3

        # Check metadata for suspicious indicators
        for event in session.events:
            if event.metadata.get("suspicious"):
                score += 0.1
                break
            if event.metadata.get("cryptominer"):
                score += 0.5
                break

        return min(score, 1.0)  # Cap at 1.0
