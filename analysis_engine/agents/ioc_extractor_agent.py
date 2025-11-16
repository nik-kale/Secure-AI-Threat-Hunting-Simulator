"""
IOC (Indicator of Compromise) extraction agent.
"""
from typing import Dict, List, Set, Any, Optional
import re
import logging
import asyncio

from analysis_engine.core.parser import NormalizedEvent
from analysis_engine.core.correlation import CorrelationSession

logger = logging.getLogger(__name__)

# Optional LLM integration
try:
    from analysis_engine.llm import LLMProvider, get_prompt
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.info("LLM integration not available. Using template-based IOC extraction.")

# Optional threat intelligence integration
try:
    from analysis_engine.threat_intel import IOCEnricher
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    logger.info("Threat intelligence integration not available.")


class IocExtractorAgent:
    """
    Extracts indicators of compromise from telemetry events.

    Supports both LLM-based and template-based extraction with
    automatic fallback to templates if LLM is unavailable.
    """

    def __init__(
        self,
        llm_provider: Optional['LLMProvider'] = None,
        use_llm: bool = True,
        threat_intel_enricher: Optional['IOCEnricher'] = None,
        enable_enrichment: bool = True
    ):
        """
        Initialize the IOC extractor.

        Args:
            llm_provider: Optional LLM provider instance for AI-powered extraction
            use_llm: Whether to use LLM when available (default: True)
            threat_intel_enricher: Optional threat intelligence enricher
            enable_enrichment: Whether to enrich IOCs with threat intel (default: True)
        """
        self.ioc_patterns = {
            "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "domain": re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I),
            "api_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "arn": re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9:/_-]+'),
        }
        self.llm_provider = llm_provider if LLM_AVAILABLE else None
        self.use_llm = use_llm and LLM_AVAILABLE and llm_provider is not None

        self.threat_intel_enricher = threat_intel_enricher if THREAT_INTEL_AVAILABLE else None
        self.enable_enrichment = enable_enrichment and THREAT_INTEL_AVAILABLE and threat_intel_enricher is not None

        if self.use_llm:
            logger.info("IocExtractorAgent initialized with LLM support")
        else:
            logger.info("IocExtractorAgent using template-based extraction")

        if self.enable_enrichment:
            logger.info("IocExtractorAgent initialized with threat intelligence enrichment")
        else:
            logger.info("IocExtractorAgent running without threat intelligence enrichment")

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

        Uses LLM if available, otherwise falls back to template-based extraction.
        Optionally enriches IOCs with threat intelligence.

        Args:
            session: Correlation session

        Returns:
            Comprehensive IOC report with optional threat intelligence enrichment
        """
        if self.use_llm:
            try:
                # Try LLM-based extraction
                return asyncio.run(self._extract_from_session_llm(session))
            except Exception as e:
                logger.warning(f"LLM IOC extraction failed: {e}. Falling back to template-based.")
                # Fall through to template-based extraction

        # Template-based extraction (fallback or default)
        ioc_report = self._extract_from_session_template(session)

        # Enrich with threat intelligence if enabled
        if self.enable_enrichment:
            try:
                ioc_report = asyncio.run(self._enrich_ioc_report(ioc_report))
            except Exception as e:
                logger.warning(f"Threat intelligence enrichment failed: {e}")
                ioc_report["enrichment_error"] = str(e)

        return ioc_report

    async def _extract_from_session_llm(self, session: CorrelationSession) -> Dict[str, Any]:
        """Extract IOCs using LLM."""
        # Convert events to dict format for LLM
        events_data = []
        for event in session.events:
            events_data.append({
                "timestamp": str(event.timestamp),
                "event_type": event.event_type,
                "principal": event.principal,
                "action": event.action,
                "resource": event.resource,
                "status": event.status,
                "source_ip": event.source_ip,
                "user_agent": event.user_agent,
                "metadata": event.metadata,
            })

        # Get prompt template
        prompt = get_prompt("ioc_extraction", mode="detailed")

        # Call LLM
        ioc_data = await self.llm_provider.extract_iocs(
            events=events_data,
            prompt_template=prompt
        )

        # Also run template-based extraction to supplement LLM results
        template_iocs = self._extract_from_session_template(session)

        # Merge LLM and template results
        merged_report = {
            "iocs": {**template_iocs.get("iocs", {}), **ioc_data.get("iocs", {})},
            "severity_classified": template_iocs.get("severity_classified", {}),
            "summary": ioc_data.get("raw_analysis", template_iocs.get("summary", "")),
            "generation_method": "llm",
            "llm_provider": self.llm_provider.__class__.__name__,
            "llm_analysis": ioc_data.get("raw_analysis", "")
        }

        # Enrich with threat intelligence if enabled
        if self.enable_enrichment:
            try:
                merged_report = await self._enrich_ioc_report(merged_report)
            except Exception as e:
                logger.warning(f"Threat intelligence enrichment failed: {e}")
                merged_report["enrichment_error"] = str(e)

        logger.info("Extracted IOCs using LLM")
        return merged_report

    async def _enrich_ioc_report(self, ioc_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich IOC report with threat intelligence.

        Args:
            ioc_report: IOC report from extraction

        Returns:
            Enhanced report with threat intelligence data
        """
        if not self.threat_intel_enricher:
            return ioc_report

        logger.info("Enriching IOC report with threat intelligence")

        try:
            enriched_report = await self.threat_intel_enricher.enrich_ioc_report(ioc_report)
            logger.info("IOC report enrichment completed successfully")
            return enriched_report
        except Exception as e:
            logger.error(f"Error enriching IOC report: {e}")
            # Return original report with error information
            ioc_report["enrichment_error"] = str(e)
            return ioc_report

    def _extract_from_session_template(self, session: CorrelationSession) -> Dict[str, Any]:
        """Extract IOCs using templates (original implementation)."""
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
            "generation_method": "template"
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
