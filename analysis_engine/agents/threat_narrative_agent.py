"""
Threat narrative generation agent.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import asyncio

from analysis_engine.core.correlation import CorrelationSession
from analysis_engine.core.kill_chain import KillChainMapper
from analysis_engine.core.mitre_mapper import MitreMapper

logger = logging.getLogger(__name__)

# Optional LLM integration
try:
    from analysis_engine.llm import LLMProvider, get_prompt
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.info("LLM integration not available. Using template-based narrative generation.")


class ThreatNarrativeAgent:
    """
    Generates human-readable threat narratives from analysis results.

    Supports both LLM-based and template-based narrative generation with
    automatic fallback to templates if LLM is unavailable.
    """

    def __init__(self, llm_provider: Optional['LLMProvider'] = None, use_llm: bool = True):
        """
        Initialize the narrative agent.

        Args:
            llm_provider: Optional LLM provider instance for AI-powered narratives
            use_llm: Whether to use LLM when available (default: True)
        """
        self.kill_chain_mapper = KillChainMapper()
        self.mitre_mapper = MitreMapper()
        self.llm_provider = llm_provider if LLM_AVAILABLE else None
        self.use_llm = use_llm and LLM_AVAILABLE and llm_provider is not None

        if self.use_llm:
            logger.info("ThreatNarrativeAgent initialized with LLM support")
        else:
            logger.info("ThreatNarrativeAgent using template-based generation")

    def generate_narrative(
        self,
        session: CorrelationSession,
        kill_chain_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive threat narrative.

        Uses LLM if available, otherwise falls back to template-based generation.

        Args:
            session: Correlation session
            kill_chain_data: Kill chain mapping results
            mitre_data: MITRE ATT&CK mapping results
            ioc_data: IOC extraction results

        Returns:
            Narrative report
        """
        if self.use_llm:
            try:
                # Try LLM-based generation
                return asyncio.run(self._generate_narrative_llm(
                    session, kill_chain_data, mitre_data, ioc_data
                ))
            except Exception as e:
                logger.warning(f"LLM narrative generation failed: {e}. Falling back to template-based.")
                # Fall through to template-based generation

        # Template-based generation (fallback or default)
        return self._generate_narrative_template(
            session, kill_chain_data, mitre_data, ioc_data
        )

    async def _generate_narrative_llm(
        self,
        session: CorrelationSession,
        kill_chain_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate narrative using LLM."""
        # Prepare session data for LLM
        session_data = {
            "session_id": session.session_id,
            "duration_seconds": session.duration_seconds(),
            "num_events": len(session.events),
            "risk_score": session.risk_score,
            "start_time": str(session.start_time) if session.start_time else "N/A",
            "end_time": str(session.end_time) if session.end_time else "N/A",
        }

        # Get prompt template
        prompt = get_prompt("narrative", mode="detailed")

        # Call LLM
        narrative = await self.llm_provider.generate_narrative(
            session_data=session_data,
            kill_chain_data=kill_chain_data,
            mitre_data=mitre_data,
            ioc_data=ioc_data,
            prompt_template=prompt
        )

        # Add metadata
        narrative["generation_method"] = "llm"
        narrative["llm_provider"] = self.llm_provider.__class__.__name__

        logger.info("Generated narrative using LLM")
        return narrative

    def _generate_narrative_template(
        self,
        session: CorrelationSession,
        kill_chain_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate narrative using templates (original implementation)."""
        narrative = {
            "executive_summary": self._generate_executive_summary(
                session, kill_chain_data, mitre_data
            ),
            "attack_timeline": self._generate_attack_timeline(session, kill_chain_data),
            "detailed_analysis": self._generate_detailed_analysis(
                session, kill_chain_data, mitre_data, ioc_data
            ),
            "impact_assessment": self._generate_impact_assessment(session, ioc_data),
            "recommended_actions": self._generate_recommended_actions(session, mitre_data),
            "generation_method": "template"
        }

        return narrative

    def _generate_executive_summary(
        self,
        session: CorrelationSession,
        kill_chain_data: Dict[str, Any],
        mitre_data: Dict[str, Any]
    ) -> str:
        """Generate executive summary."""
        lines = []

        # Determine attack type from MITRE techniques
        attack_type = self._determine_attack_type(mitre_data)

        duration = session.duration_seconds() / 60  # minutes

        lines.append(f"## Executive Summary\n")
        lines.append(
            f"A {attack_type} attack was detected spanning {duration:.1f} minutes "
            f"with {len(session.events)} total events. "
        )

        # Kill chain coverage
        num_stages = kill_chain_data.get("num_stages", 0)
        lines.append(
            f"The attack progressed through {num_stages} stages of the cyber kill chain, "
            f"demonstrating a {self._assess_sophistication(num_stages)} level of sophistication. "
        )

        # MITRE techniques
        num_techniques = mitre_data.get("num_techniques", 0)
        lines.append(
            f"Analysis identified {num_techniques} distinct MITRE ATT&CK techniques "
            f"across {len(mitre_data.get('tactics', []))} tactical categories."
        )

        # Risk assessment
        risk_level = self._assess_risk_level(session)
        lines.append(f"\n**Overall Risk Level:** {risk_level.upper()}")

        return "\n".join(lines)

    def _generate_attack_timeline(
        self,
        session: CorrelationSession,
        kill_chain_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate chronological attack timeline."""
        timeline = self.kill_chain_mapper.generate_timeline(session)

        # Group by kill chain stage
        timeline_with_context = []

        for entry in timeline:
            timeline_with_context.append({
                **entry,
                "narrative": self._generate_event_narrative(entry),
            })

        return timeline_with_context

    def _generate_detailed_analysis(
        self,
        session: CorrelationSession,
        kill_chain_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any]
    ) -> str:
        """Generate detailed analysis section."""
        lines = []

        lines.append("## Detailed Analysis\n")

        # Kill chain breakdown
        lines.append("### Attack Progression (Kill Chain)\n")
        for stage, stage_data in kill_chain_data.get("stages", {}).items():
            num_events = stage_data.get("num_events", 0)
            lines.append(f"**{stage.replace('_', ' ').title()}** ({num_events} events)")
            lines.append(f"  - {self._describe_kill_chain_stage(stage, session)}")
            lines.append("")

        # MITRE techniques
        lines.append("### MITRE ATT&CK Techniques\n")
        for tech_id, tech_info in mitre_data.get("techniques", {}).items():
            lines.append(
                f"**{tech_id}: {tech_info['technique_name']}** "
                f"({tech_info['num_events']} events)"
            )
            lines.append(f"  - Tactic: {tech_info['tactic']}")
            lines.append(f"  - {tech_info['description']}")
            lines.append("")

        # IOC summary
        if ioc_data.get("iocs"):
            lines.append("### Indicators of Compromise\n")
            lines.append(ioc_data.get("summary", "No IOCs identified"))
            lines.append("")

        return "\n".join(lines)

    def _generate_impact_assessment(
        self,
        session: CorrelationSession,
        ioc_data: Dict[str, Any]
    ) -> str:
        """Generate impact assessment."""
        lines = []

        lines.append("## Impact Assessment\n")

        # Compromised accounts
        compromised_principals = ioc_data.get("iocs", {}).get("principals", [])
        if compromised_principals:
            lines.append(f"**Compromised Accounts:** {len(compromised_principals)}")
            for principal in compromised_principals[:5]:
                lines.append(f"  - {principal}")
            if len(compromised_principals) > 5:
                lines.append(f"  - ... and {len(compromised_principals) - 5} more")
            lines.append("")

        # Accessed resources
        accessed_resources = ioc_data.get("iocs", {}).get("resources", [])
        if accessed_resources:
            lines.append(f"**Accessed/Targeted Resources:** {len(accessed_resources)}")
            for resource in accessed_resources[:5]:
                lines.append(f"  - {resource}")
            if len(accessed_resources) > 5:
                lines.append(f"  - ... and {len(accessed_resources) - 5} more")
            lines.append("")

        # Data exfiltration
        exfil_events = [
            e for e in session.events
            if e.metadata.get("data_exfiltration")
        ]
        if exfil_events:
            lines.append(f"**Data Exfiltration:** {len(exfil_events)} potential exfiltration events detected")
            lines.append("")

        return "\n".join(lines)

    def _generate_recommended_actions(
        self,
        session: CorrelationSession,
        mitre_data: Dict[str, Any]
    ) -> List[str]:
        """Generate recommended response actions."""
        actions = []

        # Immediate actions based on attack type
        techniques = mitre_data.get("technique_ids", [])

        if "T1078.004" in techniques or any("T1136" in t for t in techniques):
            actions.append({
                "priority": "CRITICAL",
                "action": "Revoke credentials for all compromised accounts immediately",
                "details": "Identified compromised or unauthorized cloud accounts"
            })

        if "T1110.004" in techniques:
            actions.append({
                "priority": "HIGH",
                "action": "Implement rate limiting and account lockout policies",
                "details": "Credential stuffing attack detected"
            })

        if "T1548" in techniques or "T1548.005" in techniques:
            actions.append({
                "priority": "CRITICAL",
                "action": "Review and restrict IAM PassRole permissions",
                "details": "Privilege escalation via PassRole detected"
            })

        if "T1611" in techniques:
            actions.append({
                "priority": "CRITICAL",
                "action": "Isolate and terminate compromised containers",
                "details": "Container escape detected"
            })

        if "T1496" in techniques:
            actions.append({
                "priority": "HIGH",
                "action": "Identify and terminate unauthorized workloads",
                "details": "Resource hijacking (cryptomining) detected"
            })

        # General actions
        actions.extend([
            {
                "priority": "HIGH",
                "action": "Conduct forensic analysis of all session events",
                "details": "Preserve logs and analyze full attack timeline"
            },
            {
                "priority": "MEDIUM",
                "action": "Review and update detection rules",
                "details": "Improve monitoring for similar attack patterns"
            },
            {
                "priority": "MEDIUM",
                "action": "Conduct security posture review",
                "details": "Identify and remediate similar vulnerabilities"
            },
        ])

        return actions

    def _determine_attack_type(self, mitre_data: Dict[str, Any]) -> str:
        """Determine primary attack type from MITRE techniques."""
        techniques = mitre_data.get("technique_ids", [])

        if "T1548.005" in techniques or "T1136.003" in techniques:
            return "privilege escalation"
        elif "T1110.004" in techniques:
            return "credential stuffing"
        elif "T1611" in techniques:
            return "container escape"
        elif "T1496" in techniques:
            return "resource hijacking"
        else:
            return "multi-stage"

    def _assess_sophistication(self, num_stages: int) -> str:
        """Assess attack sophistication."""
        if num_stages >= 5:
            return "high"
        elif num_stages >= 3:
            return "moderate"
        else:
            return "low"

    def _assess_risk_level(self, session: CorrelationSession) -> str:
        """Assess overall risk level."""
        if session.risk_score >= 0.8:
            return "critical"
        elif session.risk_score >= 0.6:
            return "high"
        elif session.risk_score >= 0.4:
            return "medium"
        else:
            return "low"

    def _describe_kill_chain_stage(self, stage: str, session: CorrelationSession) -> str:
        """Generate description for a kill chain stage."""
        descriptions = {
            "reconnaissance": "Attacker enumerated cloud resources and permissions to identify attack paths",
            "weaponization": "Attacker prepared attack payloads and tools",
            "delivery": "Initial access achieved through compromised credentials or exploits",
            "exploitation": "Vulnerabilities exploited to gain unauthorized access or escalate privileges",
            "installation": "Persistence mechanisms established for long-term access",
            "command_and_control": "Communication channels established for ongoing control",
            "actions_on_objectives": "Attacker accessed sensitive data and achieved primary objectives",
        }
        return descriptions.get(stage, "Activity detected in this stage")

    def _generate_event_narrative(self, event_entry: Dict[str, Any]) -> str:
        """Generate narrative for a single event."""
        principal = event_entry.get("principal", "Unknown actor")
        action = event_entry.get("action", "performed action")
        resource = event_entry.get("resource", "")
        status = event_entry.get("status", "")

        narrative = f"{principal} {action}"

        if resource:
            narrative += f" on {resource}"

        if status == "failure":
            narrative += " (attempt failed)"
        elif status == "denied":
            narrative += " (access denied)"

        return narrative
