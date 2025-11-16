"""
Lockheed Martin Cyber Kill Chain mapper.
"""
from typing import Dict, List, Set, Any, Optional
from enum import Enum
import logging

from .parser import NormalizedEvent
from .correlation import CorrelationSession

logger = logging.getLogger(__name__)


class KillChainStage(Enum):
    """Lockheed Martin Cyber Kill Chain stages."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


# Mapping of event patterns to kill chain stages
KILL_CHAIN_MAPPING = {
    # Reconnaissance
    KillChainStage.RECONNAISSANCE: [
        "iam.list_roles",
        "iam.list_users",
        "iam.list_policies",
        "iam.get_user",
        "iam.get_role",
        "iam.get_policy",
        "iam.list_attached_user_policies",
        "ec2.describe_instances",
        "s3.list_buckets",
        "api.get",
    ],

    # Weaponization (preparing attack)
    KillChainStage.WEAPONIZATION: [
        "lambda.create_function",
        "lambda.update_function_code",
    ],

    # Delivery
    KillChainStage.DELIVERY: [
        "api.authenticate",
        "api.login",
        "s3.put_object",
    ],

    # Exploitation
    KillChainStage.EXPLOITATION: [
        "iam.pass_role",
        "lambda.invoke",
        "container.exec",
        "ec2.run_instance",
    ],

    # Installation (persistence)
    KillChainStage.INSTALLATION: [
        "iam.create_role",
        "iam.create_user",
        "iam.attach_user_policy",
        "iam.put_role_policy",
        "iam.create_access_key",
        "lambda.create_function",
    ],

    # Command and Control
    KillChainStage.COMMAND_AND_CONTROL: [
        "network.flow",
    ],

    # Actions on Objectives
    KillChainStage.ACTIONS_ON_OBJECTIVES: [
        "s3.get_object",
        "s3.put_object",
        "secretsmanager.get_secret_value",
    ],
}


class KillChainMapper:
    """Maps events and sessions to kill chain stages."""

    def __init__(self):
        """Initialize the kill chain mapper."""
        # Create reverse mapping for faster lookup
        self.event_type_to_stage: Dict[str, KillChainStage] = {}

        for stage, event_types in KILL_CHAIN_MAPPING.items():
            for event_type in event_types:
                self.event_type_to_stage[event_type] = stage

    def map_event(self, event: NormalizedEvent) -> Optional[KillChainStage]:
        """
        Map a single event to a kill chain stage.

        Args:
            event: Normalized event

        Returns:
            Kill chain stage or None
        """
        # Check explicit metadata first
        if "attack_stage" in event.metadata:
            stage_name = event.metadata["attack_stage"]
            # Map attack stage names to kill chain
            stage_mapping = {
                "reconnaissance": KillChainStage.RECONNAISSANCE,
                "initial_access": KillChainStage.DELIVERY,
                "privilege_escalation": KillChainStage.EXPLOITATION,
                "persistence": KillChainStage.INSTALLATION,
                "credential_access": KillChainStage.EXPLOITATION,
                "lateral_movement": KillChainStage.COMMAND_AND_CONTROL,
                "container_escape": KillChainStage.EXPLOITATION,
                "impact": KillChainStage.ACTIONS_ON_OBJECTIVES,
                "validation": KillChainStage.RECONNAISSANCE,
                "credential_stuffing": KillChainStage.DELIVERY,
            }
            return stage_mapping.get(stage_name)

        # Otherwise use event type mapping
        return self.event_type_to_stage.get(event.event_type)

    def map_session(self, session: CorrelationSession) -> Dict[str, Any]:
        """
        Map a session's events to kill chain stages.

        Args:
            session: Correlation session

        Returns:
            Dictionary with stage information
        """
        stage_events: Dict[KillChainStage, List[NormalizedEvent]] = {
            stage: [] for stage in KillChainStage
        }

        for event in session.events:
            stage = self.map_event(event)
            if stage:
                stage_events[stage].append(event)

        # Calculate coverage
        active_stages = [
            stage for stage, events in stage_events.items()
            if len(events) > 0
        ]

        result = {
            "stages": {
                stage.value: {
                    "num_events": len(events),
                    "event_ids": [e.event_id for e in events[:5]],  # Sample
                }
                for stage, events in stage_events.items()
                if len(events) > 0
            },
            "active_stages": [s.value for s in active_stages],
            "num_stages": len(active_stages),
            "coverage": len(active_stages) / len(KillChainStage),
        }

        return result

    def generate_timeline(
        self,
        session: CorrelationSession
    ) -> List[Dict[str, Any]]:
        """
        Generate a chronological timeline with kill chain stages.

        Args:
            session: Correlation session

        Returns:
            List of timeline entries
        """
        timeline = []

        for event in sorted(session.events, key=lambda e: e.timestamp):
            stage = self.map_event(event)

            timeline.append({
                "timestamp": event.timestamp.isoformat(),
                "event_id": event.event_id,
                "event_type": event.event_type,
                "kill_chain_stage": stage.value if stage else "unknown",
                "principal": event.principal,
                "resource": event.resource,
                "action": event.action,
                "status": event.status,
                "description": self._generate_event_description(event),
            })

        return timeline

    def _generate_event_description(self, event: NormalizedEvent) -> str:
        """Generate human-readable description of an event."""
        principal = event.principal or "Unknown"
        action = event.action or event.event_type
        resource = event.resource or "unknown resource"

        description = f"{principal} performed {action}"

        if event.resource:
            description += f" on {resource}"

        if event.status in ["failure", "denied"]:
            description += f" (FAILED)"

        return description
