"""
Event parser and normalizer.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class NormalizedEvent:
    """Normalized representation of a telemetry event."""

    event_id: str
    timestamp: datetime
    event_type: str
    event_source: str
    account_id: str
    region: str

    # Identity
    principal: Optional[str] = None
    principal_type: Optional[str] = None

    # Network
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None

    # Resource
    resource: Optional[str] = None
    resource_type: Optional[str] = None

    # Action
    action: Optional[str] = None
    status: str = "unknown"

    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)
    request_parameters: Dict[str, Any] = field(default_factory=dict)
    response_elements: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    severity: str = "info"
    tags: List[str] = field(default_factory=list)

    # Original raw event
    raw_event: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "event_source": self.event_source,
            "account_id": self.account_id,
            "region": self.region,
            "principal": self.principal,
            "principal_type": self.principal_type,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "resource": self.resource,
            "resource_type": self.resource_type,
            "action": self.action,
            "status": self.status,
            "metadata": self.metadata,
            "session_id": self.session_id,
            "severity": self.severity,
            "tags": self.tags,
        }


class EventParser:
    """Parses and normalizes raw telemetry events."""

    @staticmethod
    def parse_timestamp(timestamp_str: str) -> datetime:
        """Parse ISO 8601 timestamp."""
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            # Try with microseconds
            try:
                return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                # Fallback to datetime.fromisoformat
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

    @classmethod
    def parse_event(cls, raw_event: Dict[str, Any]) -> NormalizedEvent:
        """
        Parse and normalize a raw telemetry event.

        Args:
            raw_event: Raw event dictionary

        Returns:
            Normalized event object
        """
        try:
            timestamp = cls.parse_timestamp(raw_event["timestamp"])
        except Exception as e:
            logger.warning(f"Failed to parse timestamp: {e}, using current time")
            timestamp = datetime.utcnow()

        normalized = NormalizedEvent(
            event_id=raw_event.get("event_id", "unknown"),
            timestamp=timestamp,
            event_type=raw_event.get("event_type", "unknown"),
            event_source=raw_event.get("event_source", "unknown"),
            account_id=raw_event.get("account_id", "unknown"),
            region=raw_event.get("region", "unknown"),
            principal=raw_event.get("principal"),
            principal_type=raw_event.get("principal_type"),
            source_ip=raw_event.get("source_ip"),
            user_agent=raw_event.get("user_agent"),
            resource=raw_event.get("resource"),
            resource_type=raw_event.get("resource_type"),
            action=raw_event.get("action"),
            status=raw_event.get("status", "unknown"),
            metadata=raw_event.get("metadata", {}),
            request_parameters=raw_event.get("request_parameters", {}),
            response_elements=raw_event.get("response_elements", {}),
            session_id=raw_event.get("session_id"),
            severity=raw_event.get("severity", "info"),
            tags=raw_event.get("tags", []),
            raw_event=raw_event,
        )

        return normalized

    @classmethod
    def parse_events(cls, raw_events: List[Dict[str, Any]]) -> List[NormalizedEvent]:
        """
        Parse a list of raw events.

        Args:
            raw_events: List of raw event dictionaries

        Returns:
            List of normalized events
        """
        normalized_events = []

        for raw_event in raw_events:
            try:
                normalized = cls.parse_event(raw_event)
                normalized_events.append(normalized)
            except Exception as e:
                logger.error(f"Failed to parse event {raw_event.get('event_id')}: {e}")
                continue

        logger.info(f"Parsed {len(normalized_events)}/{len(raw_events)} events successfully")
        return normalized_events

    @staticmethod
    def filter_events(
        events: List[NormalizedEvent],
        event_source: Optional[str] = None,
        event_type: Optional[str] = None,
        principal: Optional[str] = None,
        status: Optional[str] = None,
        min_severity: Optional[str] = None,
    ) -> List[NormalizedEvent]:
        """
        Filter events based on criteria.

        Args:
            events: List of normalized events
            event_source: Filter by event source
            event_type: Filter by event type
            principal: Filter by principal
            status: Filter by status
            min_severity: Minimum severity level

        Returns:
            Filtered list of events
        """
        filtered = events

        if event_source:
            filtered = [e for e in filtered if e.event_source == event_source]

        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]

        if principal:
            filtered = [e for e in filtered if e.principal == principal]

        if status:
            filtered = [e for e in filtered if e.status == status]

        if min_severity:
            severity_levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            min_level = severity_levels.get(min_severity, 0)
            filtered = [
                e for e in filtered
                if severity_levels.get(e.severity, 0) >= min_level
            ]

        return filtered
