"""
MITRE ATT&CK framework mapper.
"""
from typing import Dict, List, Set, Any
from dataclasses import dataclass
import logging

from .parser import NormalizedEvent
from .correlation import CorrelationSession

logger = logging.getLogger(__name__)


@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic: str
    description: str


# Simplified MITRE ATT&CK mapping (educational subset)
MITRE_TECHNIQUES = {
    "T1078": MitreTechnique(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        description="Adversaries may obtain and abuse credentials of existing accounts"
    ),
    "T1078.004": MitreTechnique(
        technique_id="T1078.004",
        technique_name="Valid Accounts: Cloud Accounts",
        tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        description="Valid credentials for cloud services"
    ),
    "T1087": MitreTechnique(
        technique_id="T1087",
        technique_name="Account Discovery",
        tactic="Discovery",
        description="Adversaries may attempt to get a listing of accounts"
    ),
    "T1087.004": MitreTechnique(
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account",
        tactic="Discovery",
        description="Enumerate cloud accounts and roles"
    ),
    "T1110.004": MitreTechnique(
        technique_id="T1110.004",
        technique_name="Brute Force: Credential Stuffing",
        tactic="Credential Access",
        description="Adversaries use credentials obtained from breach dumps"
    ),
    "T1136.003": MitreTechnique(
        technique_id="T1136.003",
        technique_name="Create Account: Cloud Account",
        tactic="Persistence",
        description="Create cloud accounts for persistence"
    ),
    "T1190": MitreTechnique(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Exploit web application vulnerabilities"
    ),
    "T1021": MitreTechnique(
        technique_id="T1021",
        technique_name="Remote Services",
        tactic="Lateral Movement",
        description="Use remote services for lateral movement"
    ),
    "T1496": MitreTechnique(
        technique_id="T1496",
        technique_name="Resource Hijacking",
        tactic="Impact",
        description="Leverage cloud resources for unauthorized purposes"
    ),
    "T1530": MitreTechnique(
        technique_id="T1530",
        technique_name="Data from Cloud Storage Object",
        tactic="Collection",
        description="Access data stored in cloud storage services"
    ),
    "T1548": MitreTechnique(
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation, Defense Evasion",
        description="Circumvent mechanisms to gain elevated permissions"
    ),
    "T1548.005": MitreTechnique(
        technique_id="T1548.005",
        technique_name="Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
        tactic="Privilege Escalation, Defense Evasion",
        description="Abuse cloud IAM for privilege escalation"
    ),
    "T1552.005": MitreTechnique(
        technique_id="T1552.005",
        technique_name="Unsecured Credentials: Cloud Instance Metadata API",
        tactic="Credential Access",
        description="Access credentials via cloud metadata services"
    ),
    "T1589.001": MitreTechnique(
        technique_id="T1589.001",
        technique_name="Gather Victim Identity Information",
        tactic="Reconnaissance",
        description="Collect identity information for targeting"
    ),
    "T1611": MitreTechnique(
        technique_id="T1611",
        technique_name="Escape to Host",
        tactic="Privilege Escalation",
        description="Break out of container to host system"
    ),
}


# Event pattern to MITRE technique mapping
EVENT_PATTERN_TO_TECHNIQUE = {
    # Account Discovery
    "iam.list_roles": ["T1087.004"],
    "iam.list_users": ["T1087.004"],
    "iam.list_policies": ["T1087.004"],
    "iam.get_user": ["T1087.004"],
    "iam.get_role": ["T1087.004"],
    "iam.list_attached_user_policies": ["T1087.004"],

    # Valid Accounts / Cloud Accounts
    "api.authenticate": ["T1078.004"],
    "api.login": ["T1078.004"],

    # Create Account
    "iam.create_role": ["T1136.003"],
    "iam.create_user": ["T1136.003"],
    "iam.create_access_key": ["T1136.003"],

    # Privilege Escalation
    "iam.attach_policy": ["T1548.005"],
    "iam.put_role_policy": ["T1548.005"],
    "lambda.create_function": ["T1548.005"],  # With PassRole

    # Data Access
    "s3.get_object": ["T1530"],

    # Container Escape
    "container.exec": ["T1611"],

    # Metadata API
    "api.request": ["T1552.005"],
}


class MitreMapper:
    """Maps events and sessions to MITRE ATT&CK techniques."""

    def __init__(self):
        """Initialize the MITRE mapper."""
        self.techniques = MITRE_TECHNIQUES

    def map_event(self, event: NormalizedEvent) -> List[str]:
        """
        Map a single event to MITRE techniques.

        Args:
            event: Normalized event

        Returns:
            List of MITRE technique IDs
        """
        techniques = []

        # Check for explicit metadata
        if "mitre_technique" in event.metadata:
            techniques.append(event.metadata["mitre_technique"])

        # Pattern-based mapping
        if event.event_type in EVENT_PATTERN_TO_TECHNIQUE:
            techniques.extend(EVENT_PATTERN_TO_TECHNIQUE[event.event_type])

        # Context-aware detection
        # Credential stuffing (multiple auth failures)
        if event.event_type == "api.request" and event.status == "failure":
            if event.metadata.get("authentication") == "failed":
                techniques.append("T1110.004")

        # Metadata API access
        if event.metadata.get("metadata_service"):
            techniques.append("T1552.005")

        # Container escape indicators
        if event.metadata.get("suspicious") == "container_breakout":
            techniques.append("T1611")

        # Cryptomining / resource hijacking
        if event.metadata.get("cryptominer"):
            techniques.append("T1496")

        return list(set(techniques))  # Remove duplicates

    def map_session(self, session: CorrelationSession) -> Dict[str, Any]:
        """
        Map a session's events to MITRE techniques.

        Args:
            session: Correlation session

        Returns:
            Dictionary with technique information
        """
        technique_events: Dict[str, List[NormalizedEvent]] = {}

        for event in session.events:
            techniques = self.map_event(event)

            for tech_id in techniques:
                if tech_id not in technique_events:
                    technique_events[tech_id] = []
                technique_events[tech_id].append(event)

        # Build result with technique details
        techniques_detail = {}

        for tech_id, events in technique_events.items():
            if tech_id in self.techniques:
                technique = self.techniques[tech_id]
                techniques_detail[tech_id] = {
                    "technique_id": technique.technique_id,
                    "technique_name": technique.technique_name,
                    "tactic": technique.tactic,
                    "description": technique.description,
                    "num_events": len(events),
                    "event_ids": [e.event_id for e in events[:5]],  # Sample
                }
            else:
                # Unknown technique (from metadata)
                techniques_detail[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": "Unknown",
                    "tactic": "Unknown",
                    "description": "Technique from scenario metadata",
                    "num_events": len(events),
                    "event_ids": [e.event_id for e in events[:5]],
                }

        result = {
            "techniques": techniques_detail,
            "technique_ids": list(technique_events.keys()),
            "num_techniques": len(technique_events),
            "tactics": self._extract_tactics(techniques_detail),
        }

        return result

    def _extract_tactics(self, techniques_detail: Dict[str, Any]) -> List[str]:
        """Extract unique tactics from techniques."""
        tactics = set()

        for tech_info in techniques_detail.values():
            tactic_str = tech_info.get("tactic", "")
            # Split by comma and clean
            for tactic in tactic_str.split(","):
                tactic = tactic.strip()
                if tactic:
                    tactics.add(tactic)

        return sorted(list(tactics))

    def generate_attack_matrix(
        self,
        session: CorrelationSession
    ) -> Dict[str, Any]:
        """
        Generate a MITRE ATT&CK matrix view of the attack.

        Args:
            session: Correlation session

        Returns:
            Attack matrix representation
        """
        mitre_data = self.map_session(session)

        # Organize by tactic
        tactics_matrix = {}

        for tech_id, tech_info in mitre_data["techniques"].items():
            tactics = tech_info["tactic"].split(",")

            for tactic in tactics:
                tactic = tactic.strip()
                if tactic not in tactics_matrix:
                    tactics_matrix[tactic] = []

                tactics_matrix[tactic].append({
                    "technique_id": tech_id,
                    "technique_name": tech_info["technique_name"],
                    "num_events": tech_info["num_events"],
                })

        return {
            "matrix": tactics_matrix,
            "total_tactics": len(tactics_matrix),
            "total_techniques": mitre_data["num_techniques"],
        }
