"""
IOC (Indicator of Compromise) extraction agent.
"""
from typing import Dict, List, Set, Any
import re
import logging

from analysis_engine.core.parser import NormalizedEvent
from analysis_engine.core.correlation import CorrelationSession

logger = logging.getLogger(__name__)


class IocExtractorAgent:
    """
    Extracts indicators of compromise from telemetry events.

    This is a template-based implementation that can be replaced with
    an LLM-based extractor in the future.
    """

    def __init__(self):
        """Initialize the IOC extractor."""
        self.ioc_patterns = {
            "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "domain": re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I),
            "api_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "arn": re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9:/_-]+'),
        }

    def extract_from_event(self, event: NormalizedEvent) -> Dict[str, Set[str]]:
        """
        Extract IOCs from a single event.

        Args:
            event: Normalized event

        Returns:
            Dictionary of IOC types to sets of values
        """
        iocs: Dict[str, Set[str]] = {
            "ip_addresses": set(),
            "domains": set(),
            "api_keys": set(),
            "user_agents": set(),
            "principals": set(),
            "resources": set(),
            "command_lines": set(),
        }

        # Extract IPs
        if event.source_ip:
            iocs["ip_addresses"].add(event.source_ip)

        # Extract user agents
        if event.user_agent:
            iocs["user_agents"].add(event.user_agent)

        # Extract principals (compromised accounts)
        if event.principal and self._is_suspicious(event):
            iocs["principals"].add(event.principal)

        # Extract resources (compromised/targeted)
        if event.resource and self._is_suspicious(event):
            iocs["resources"].add(event.resource)

        # Extract command lines from container events
        if event.metadata.get("command"):
            iocs["command_lines"].add(event.metadata["command"])

        # Extract from metadata
        metadata_str = str(event.metadata)

        # API keys
        api_keys = self.ioc_patterns["api_key"].findall(metadata_str)
        iocs["api_keys"].update(api_keys)

        # Domains
        domains = self.ioc_patterns["domain"].findall(metadata_str)
        # Filter out common benign domains
        benign_domains = {"amazonaws.com", "aws.amazon.com"}
        iocs["domains"].update(d for d in domains if d not in benign_domains)

        return iocs

    def extract_from_session(self, session: CorrelationSession) -> Dict[str, Any]:
        """
        Extract IOCs from a session.

        Args:
            session: Correlation session

        Returns:
            Comprehensive IOC report
        """
        # LLM_INTEGRATION_POINT
        # Replace this template-based logic with LLM call:
        # iocs = llm.extract_iocs(session.events)

        aggregated_iocs: Dict[str, Set[str]] = {
            "ip_addresses": set(),
            "domains": set(),
            "api_keys": set(),
            "user_agents": set(),
            "principals": set(),
            "resources": set(),
            "command_lines": set(),
        }

        for event in session.events:
            event_iocs = self.extract_from_event(event)

            for ioc_type, values in event_iocs.items():
                aggregated_iocs[ioc_type].update(values)

        # Classify IOC severity
        severity_classified = self._classify_ioc_severity(aggregated_iocs, session)

        # Convert sets to lists for JSON serialization
        ioc_report = {
            "iocs": {
                ioc_type: sorted(list(values))
                for ioc_type, values in aggregated_iocs.items()
                if values
            },
            "severity_classified": severity_classified,
            "summary": self._generate_ioc_summary(aggregated_iocs, session),
        }

        logger.info(f"Extracted {sum(len(v) for v in aggregated_iocs.values())} IOCs from session")
        return ioc_report

    def _is_suspicious(self, event: NormalizedEvent) -> bool:
        """Check if event is suspicious."""
        # Check for explicit suspicious markers
        if event.metadata.get("suspicious"):
            return True
        if event.metadata.get("attack_stage"):
            return True
        if event.metadata.get("cryptominer"):
            return True
        if event.metadata.get("compromised_account"):
            return True

        # Failed authentication/authorization
        if event.status in ["failure", "denied", "error"]:
            return True

        return False

    def _classify_ioc_severity(
        self,
        iocs: Dict[str, Set[str]],
        session: CorrelationSession
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Classify IOCs by severity."""
        classified = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }

        # API keys are always critical if found
        for api_key in iocs.get("api_keys", []):
            classified["critical"].append({
                "type": "api_key",
                "value": api_key[:10] + "...",  # Redacted
                "reason": "Exposed AWS API key"
            })

        # Compromised principals
        for principal in iocs.get("principals", []):
            if "admin" in principal.lower() or "root" in principal.lower():
                severity = "critical"
                reason = "Compromised administrative account"
            else:
                severity = "high"
                reason = "Compromised user account"

            classified[severity].append({
                "type": "principal",
                "value": principal,
                "reason": reason
            })

        # Suspicious IPs
        for ip in iocs.get("ip_addresses", []):
            # In real implementation, check against threat intel feeds
            classified["medium"].append({
                "type": "ip_address",
                "value": ip,
                "reason": "Suspicious source IP"
            })

        # Malicious commands
        for cmd in iocs.get("command_lines", []):
            if any(keyword in cmd for keyword in ["xmrig", "cryptominer", "chroot", "nsenter"]):
                severity = "critical"
                reason = "Malicious command execution"
            else:
                severity = "medium"
                reason = "Suspicious command"

            classified[severity].append({
                "type": "command",
                "value": cmd,
                "reason": reason
            })

        return classified

    def _generate_ioc_summary(
        self,
        iocs: Dict[str, Set[str]],
        session: CorrelationSession
    ) -> str:
        """Generate human-readable IOC summary."""
        lines = []

        total_iocs = sum(len(v) for v in iocs.values())
        lines.append(f"Extracted {total_iocs} indicators of compromise:")

        if iocs.get("ip_addresses"):
            lines.append(f"  - {len(iocs['ip_addresses'])} suspicious IP addresses")

        if iocs.get("principals"):
            lines.append(f"  - {len(iocs['principals'])} compromised accounts/roles")

        if iocs.get("resources"):
            lines.append(f"  - {len(iocs['resources'])} targeted resources")

        if iocs.get("api_keys"):
            lines.append(f"  - {len(iocs['api_keys'])} exposed API keys (CRITICAL)")

        if iocs.get("command_lines"):
            lines.append(f"  - {len(iocs['command_lines'])} malicious commands")

        if iocs.get("user_agents"):
            lines.append(f"  - {len(iocs['user_agents'])} suspicious user agents")

        if iocs.get("domains"):
            lines.append(f"  - {len(iocs['domains'])} suspicious domains")

        return "\n".join(lines)
