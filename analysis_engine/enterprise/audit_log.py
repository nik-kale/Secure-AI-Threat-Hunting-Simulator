"""Enterprise audit logging for compliance and security."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import hashlib

class AuditEventType(str, Enum):
    """Types of auditable events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    CONFIGURATION_CHANGE = "configuration_change"
    USER_MANAGEMENT = "user_management"
    ROLE_ASSIGNMENT = "role_assignment"
    POLICY_CHANGE = "policy_change"
    EXPORT = "export"
    IMPORT = "import"
    INTEGRATION_ACCESS = "integration_access"
    API_ACCESS = "api_access"
    SYSTEM_EVENT = "system_event"

class AuditSeverity(str, Enum):
    """Audit event severity."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class AuditEvent:
    """Individual audit log entry."""
    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    severity: AuditSeverity
    actor_id: str  # User or service performing action
    actor_type: str  # user, service_account, api_key, system
    action: str  # Specific action taken
    resource_type: str  # Type of resource acted upon
    resource_id: Optional[str]  # Specific resource instance
    tenant_id: Optional[str]  # Multi-tenancy support
    source_ip: Optional[str]  # Source IP address
    user_agent: Optional[str]  # Client user agent
    outcome: str  # success, failure, partial
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Integrity fields
    previous_event_hash: Optional[str] = None
    event_hash: Optional[str] = None

@dataclass
class AuditQuery:
    """Query parameters for audit log search."""
    event_types: Optional[List[AuditEventType]] = None
    actor_ids: Optional[List[str]] = None
    resource_types: Optional[List[str]] = None
    tenant_ids: Optional[List[str]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    outcomes: Optional[List[str]] = None
    severities: Optional[List[AuditSeverity]] = None
    limit: int = 100

class AuditLogger:
    """Enterprise audit logging system with tamper detection."""

    def __init__(self, tenant_id: Optional[str] = None):
        self.tenant_id = tenant_id
        self.events: List[AuditEvent] = []
        self.last_event_hash: Optional[str] = None
        self.tamper_detected = False

    def log_event(
        self,
        event_type: AuditEventType,
        actor_id: str,
        actor_type: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        outcome: str = "success",
        severity: AuditSeverity = AuditSeverity.INFO,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """Log an auditable event.

        Args:
            event_type: Type of event
            actor_id: Who performed the action
            actor_type: Type of actor
            action: Action performed
            resource_type: Type of resource
            resource_id: Specific resource
            outcome: Result of action
            severity: Event severity
            source_ip: Source IP
            user_agent: Client user agent
            details: Additional event details
            metadata: Event metadata

        Returns:
            Created audit event
        """
        event_id = f"audit-{len(self.events):08d}"

        event = AuditEvent(
            event_id=event_id,
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            actor_id=actor_id,
            actor_type=actor_type,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            tenant_id=self.tenant_id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome=outcome,
            details=details or {},
            metadata=metadata or {},
            previous_event_hash=self.last_event_hash
        )

        # Calculate event hash for integrity
        event.event_hash = self._calculate_event_hash(event)
        self.last_event_hash = event.event_hash

        self.events.append(event)

        return event

    def _calculate_event_hash(self, event: AuditEvent) -> str:
        """Calculate SHA-256 hash of event for tamper detection.

        Args:
            event: Event to hash

        Returns:
            Hex-encoded hash
        """
        # Create deterministic string representation
        hash_input = (
            f"{event.event_id}|{event.timestamp.isoformat()}|"
            f"{event.event_type.value}|{event.actor_id}|{event.action}|"
            f"{event.resource_type}|{event.resource_id}|{event.outcome}|"
            f"{event.previous_event_hash}|{json.dumps(event.details, sort_keys=True)}"
        )

        return hashlib.sha256(hash_input.encode()).hexdigest()

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify audit log integrity by checking event hashes.

        Returns:
            Verification result with details of any tampering
        """
        if not self.events:
            return {"verified": True, "tampered_events": []}

        tampered_events = []
        expected_previous_hash = None

        for event in self.events:
            # Check previous hash linkage
            if event.previous_event_hash != expected_previous_hash:
                tampered_events.append({
                    "event_id": event.event_id,
                    "reason": "Previous hash mismatch",
                    "expected": expected_previous_hash,
                    "actual": event.previous_event_hash
                })

            # Verify event hash
            calculated_hash = self._calculate_event_hash(event)
            if calculated_hash != event.event_hash:
                tampered_events.append({
                    "event_id": event.event_id,
                    "reason": "Event hash mismatch",
                    "expected": event.event_hash,
                    "calculated": calculated_hash
                })

            expected_previous_hash = event.event_hash

        self.tamper_detected = len(tampered_events) > 0

        return {
            "verified": not self.tamper_detected,
            "total_events": len(self.events),
            "tampered_events": tampered_events
        }

    def query_events(self, query: AuditQuery) -> List[AuditEvent]:
        """Query audit events with filters.

        Args:
            query: Query parameters

        Returns:
            Matching audit events
        """
        results = self.events.copy()

        # Filter by event types
        if query.event_types:
            results = [e for e in results if e.event_type in query.event_types]

        # Filter by actors
        if query.actor_ids:
            results = [e for e in results if e.actor_id in query.actor_ids]

        # Filter by resource types
        if query.resource_types:
            results = [e for e in results if e.resource_type in query.resource_types]

        # Filter by tenant
        if query.tenant_ids:
            results = [e for e in results if e.tenant_id in query.tenant_ids]

        # Filter by time range
        if query.start_time:
            results = [e for e in results if e.timestamp >= query.start_time]
        if query.end_time:
            results = [e for e in results if e.timestamp <= query.end_time]

        # Filter by outcome
        if query.outcomes:
            results = [e for e in results if e.outcome in query.outcomes]

        # Filter by severity
        if query.severities:
            results = [e for e in results if e.severity in query.severities]

        # Sort by timestamp descending
        results = sorted(results, key=lambda e: e.timestamp, reverse=True)

        return results[:query.limit]

    def get_activity_summary(
        self,
        actor_id: str,
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """Get activity summary for an actor.

        Args:
            actor_id: Actor to summarize
            time_window_hours: Time window in hours

        Returns:
            Activity summary
        """
        cutoff_time = datetime.now() - timedelta(hours=time_window_hours)

        events = [
            e for e in self.events
            if e.actor_id == actor_id and e.timestamp >= cutoff_time
        ]

        if not events:
            return {
                "actor_id": actor_id,
                "total_events": 0,
                "time_window_hours": time_window_hours
            }

        event_types = {}
        outcomes = {"success": 0, "failure": 0, "partial": 0}
        resource_types = {}

        for event in events:
            # Count event types
            event_type = event.event_type.value
            event_types[event_type] = event_types.get(event_type, 0) + 1

            # Count outcomes
            outcomes[event.outcome] = outcomes.get(event.outcome, 0) + 1

            # Count resource types
            resource_types[event.resource_type] = resource_types.get(event.resource_type, 0) + 1

        return {
            "actor_id": actor_id,
            "total_events": len(events),
            "time_window_hours": time_window_hours,
            "event_types": event_types,
            "outcomes": outcomes,
            "resource_types": resource_types,
            "first_event": events[-1].timestamp.isoformat(),
            "last_event": events[0].timestamp.isoformat()
        }

    def detect_anomalies(self, time_window_hours: int = 24) -> List[Dict[str, Any]]:
        """Detect anomalous audit patterns.

        Args:
            time_window_hours: Time window to analyze

        Returns:
            List of detected anomalies
        """
        cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
        recent_events = [e for e in self.events if e.timestamp >= cutoff_time]

        anomalies = []

        # Detect excessive failed authentication
        failed_auth = [
            e for e in recent_events
            if e.event_type == AuditEventType.AUTHENTICATION and e.outcome == "failure"
        ]

        actor_failures = {}
        for event in failed_auth:
            actor_failures[event.actor_id] = actor_failures.get(event.actor_id, 0) + 1

        for actor_id, failure_count in actor_failures.items():
            if failure_count >= 5:
                anomalies.append({
                    "type": "excessive_failed_auth",
                    "actor_id": actor_id,
                    "failure_count": failure_count,
                    "severity": "high",
                    "description": f"Actor {actor_id} had {failure_count} failed authentication attempts"
                })

        # Detect unusual time access
        for event in recent_events:
            hour = event.timestamp.hour
            if hour < 6 or hour > 22:  # Outside business hours
                anomalies.append({
                    "type": "unusual_time_access",
                    "actor_id": event.actor_id,
                    "timestamp": event.timestamp.isoformat(),
                    "severity": "medium",
                    "description": f"Access at unusual time: {event.timestamp.hour}:00"
                })

        # Detect bulk data export
        export_events = [
            e for e in recent_events
            if e.event_type == AuditEventType.EXPORT
        ]

        if len(export_events) > 10:
            anomalies.append({
                "type": "bulk_export",
                "export_count": len(export_events),
                "severity": "critical",
                "description": f"{len(export_events)} export events detected in {time_window_hours} hours"
            })

        # Detect privilege escalation attempts
        priv_changes = [
            e for e in recent_events
            if e.event_type == AuditEventType.ROLE_ASSIGNMENT
        ]

        for event in priv_changes:
            if event.outcome == "success":
                anomalies.append({
                    "type": "privilege_escalation",
                    "actor_id": event.actor_id,
                    "resource_id": event.resource_id,
                    "timestamp": event.timestamp.isoformat(),
                    "severity": "high",
                    "description": f"Privilege escalation by {event.actor_id}"
                })

        return anomalies

    def export_compliance_report(
        self,
        start_time: datetime,
        end_time: datetime,
        format: str = "json"
    ) -> str:
        """Export compliance report for audit period.

        Args:
            start_time: Report start time
            end_time: Report end time
            format: Export format (json, csv)

        Returns:
            Formatted report
        """
        query = AuditQuery(
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )

        events = self.query_events(query)

        report = {
            "report_generated": datetime.now().isoformat(),
            "period_start": start_time.isoformat(),
            "period_end": end_time.isoformat(),
            "total_events": len(events),
            "integrity_verified": not self.tamper_detected,
            "event_breakdown": {},
            "actor_summary": {},
            "critical_events": []
        }

        # Event type breakdown
        for event in events:
            event_type = event.event_type.value
            report["event_breakdown"][event_type] = report["event_breakdown"].get(event_type, 0) + 1

        # Actor summary
        for event in events:
            if event.actor_id not in report["actor_summary"]:
                report["actor_summary"][event.actor_id] = {
                    "total_events": 0,
                    "failed_events": 0,
                    "critical_events": 0
                }

            report["actor_summary"][event.actor_id]["total_events"] += 1

            if event.outcome == "failure":
                report["actor_summary"][event.actor_id]["failed_events"] += 1

            if event.severity == AuditSeverity.CRITICAL:
                report["actor_summary"][event.actor_id]["critical_events"] += 1

        # Critical events
        report["critical_events"] = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "actor_id": e.actor_id,
                "action": e.action,
                "resource": f"{e.resource_type}/{e.resource_id}"
            }
            for e in events
            if e.severity == AuditSeverity.CRITICAL
        ]

        if format == "json":
            return json.dumps(report, indent=2)
        else:
            # CSV export would be implemented here
            return json.dumps(report, indent=2)
