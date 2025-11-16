"""
Incident response planning agent.
"""
from typing import Dict, List, Any, Optional
import logging
import asyncio

from analysis_engine.core.correlation import CorrelationSession

logger = logging.getLogger(__name__)

# Optional LLM integration
try:
    from analysis_engine.llm import LLMProvider, get_prompt
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.info("LLM integration not available. Using template-based response planning.")


class ResponsePlannerAgent:
    """
    Generates incident response plans and playbooks.

    Supports both LLM-based and template-based planning with
    automatic fallback to templates if LLM is unavailable.
    """

    def __init__(self, llm_provider: Optional['LLMProvider'] = None, use_llm: bool = True):
        """
        Initialize the response planner.

        Args:
            llm_provider: Optional LLM provider instance for AI-powered planning
            use_llm: Whether to use LLM when available (default: True)
        """
        self.llm_provider = llm_provider if LLM_AVAILABLE else None
        self.use_llm = use_llm and LLM_AVAILABLE and llm_provider is not None

        if self.use_llm:
            logger.info("ResponsePlannerAgent initialized with LLM support")
        else:
            logger.info("ResponsePlannerAgent using template-based planning")

    def generate_response_plan(
        self,
        session: CorrelationSession,
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any],
        narrative_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate an incident response plan.

        Uses LLM if available, otherwise falls back to template-based planning.

        Args:
            session: Correlation session
            mitre_data: MITRE ATT&CK mapping
            ioc_data: IOC extraction results
            narrative_data: Threat narrative

        Returns:
            Response plan
        """
        if self.use_llm:
            try:
                # Try LLM-based planning
                return asyncio.run(self._generate_response_plan_llm(
                    session, mitre_data, ioc_data, narrative_data
                ))
            except Exception as e:
                logger.warning(f"LLM response planning failed: {e}. Falling back to template-based.")
                # Fall through to template-based planning

        # Template-based planning (fallback or default)
        return self._generate_response_plan_template(
            session, mitre_data, ioc_data, narrative_data
        )

    async def _generate_response_plan_llm(
        self,
        session: CorrelationSession,
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any],
        narrative_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate response plan using LLM."""
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
        prompt = get_prompt("response_planning", mode="detailed")

        # Call LLM
        plan = await self.llm_provider.plan_response(
            session_data=session_data,
            mitre_data=mitre_data,
            ioc_data=ioc_data,
            narrative_data=narrative_data,
            prompt_template=prompt
        )

        # Also generate template-based plan for structured data
        template_plan = self._generate_response_plan_template(
            session, mitre_data, ioc_data, narrative_data
        )

        # Merge LLM and template results
        merged_plan = {
            **template_plan,
            "llm_analysis": plan.get("raw_plan", ""),
            "generation_method": "llm",
            "llm_provider": self.llm_provider.__class__.__name__,
        }

        logger.info("Generated response plan using LLM")
        return merged_plan

    def _generate_response_plan_template(
        self,
        session: CorrelationSession,
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any],
        narrative_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate response plan using templates (original implementation)."""
        plan = {
            "immediate_actions": self._generate_immediate_actions(session, ioc_data),
            "containment": self._generate_containment_steps(session, mitre_data),
            "eradication": self._generate_eradication_steps(session, mitre_data, ioc_data),
            "recovery": self._generate_recovery_steps(session),
            "lessons_learned": self._generate_lessons_learned(session, mitre_data),
            "timeline_estimate": self._estimate_response_timeline(session),
            "generation_method": "template"
        }

        return plan

    def _generate_immediate_actions(
        self,
        session: CorrelationSession,
        ioc_data: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate immediate response actions (first 15 minutes)."""
        actions = []

        # Isolate compromised accounts
        if ioc_data.get("iocs", {}).get("principals"):
            actions.append({
                "action": "Disable compromised accounts",
                "priority": "CRITICAL",
                "timeframe": "Immediate (0-5 minutes)",
                "command": "aws iam update-access-key --access-key-id <KEY> --status Inactive",
                "details": "Disable all access keys for compromised accounts"
            })

        # Block suspicious IPs
        if ioc_data.get("iocs", {}).get("ip_addresses"):
            actions.append({
                "action": "Block malicious IP addresses",
                "priority": "HIGH",
                "timeframe": "Immediate (0-5 minutes)",
                "command": "Update WAF rules / security groups to block IPs",
                "details": f"Block {len(ioc_data['iocs']['ip_addresses'])} suspicious IPs"
            })

        # Snapshot for forensics
        actions.append({
            "action": "Preserve evidence",
            "priority": "HIGH",
            "timeframe": "0-15 minutes",
            "command": "Export CloudTrail logs, create EBS snapshots",
            "details": "Preserve all logs and system state for forensic analysis"
        })

        # Alert stakeholders
        actions.append({
            "action": "Notify security team and stakeholders",
            "priority": "HIGH",
            "timeframe": "0-10 minutes",
            "command": "Send incident notification via PagerDuty/Slack",
            "details": f"Severity: {session.risk_score:.1%} risk score"
        })

        return actions

    def _generate_containment_steps(
        self,
        session: CorrelationSession,
        mitre_data: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate containment steps (15 minutes - 1 hour)."""
        steps = []

        techniques = mitre_data.get("technique_ids", [])

        # IAM-related containment
        if any("T1136" in t or "T1548" in t for t in techniques):
            steps.append({
                "action": "Review and delete unauthorized IAM resources",
                "timeframe": "15-30 minutes",
                "details": "Delete backdoor roles, users, and access keys created during attack",
                "commands": [
                    "aws iam list-roles --query 'Roles[?CreateDate>`ATTACK_START`]'",
                    "aws iam delete-role --role-name <BACKDOOR_ROLE>",
                    "aws iam delete-access-key --access-key-id <KEY>"
                ]
            })

        # Container-related containment
        if "T1611" in techniques or "T1496" in techniques:
            steps.append({
                "action": "Isolate and terminate compromised containers",
                "timeframe": "15-30 minutes",
                "details": "Stop compromised containers, update security groups to isolate workloads",
                "commands": [
                    "docker stop <CONTAINER_ID>",
                    "kubectl delete pod <POD_NAME>",
                    "Update security group rules to deny all traffic"
                ]
            })

        # Lambda containment
        if "T1548.005" in techniques:
            steps.append({
                "action": "Delete malicious Lambda functions",
                "timeframe": "15-20 minutes",
                "details": "Remove Lambda functions created during the attack",
                "commands": [
                    "aws lambda list-functions",
                    "aws lambda delete-function --function-name <MALICIOUS_FUNCTION>"
                ]
            })

        # Network containment
        steps.append({
            "action": "Implement network segmentation",
            "timeframe": "30-60 minutes",
            "details": "Update security groups and NACLs to limit lateral movement",
            "commands": [
                "Review and update VPC security group rules",
                "Implement principle of least privilege for network access"
            ]
        })

        return steps

    def _generate_eradication_steps(
        self,
        session: CorrelationSession,
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate eradication steps (1-4 hours)."""
        steps = []

        # Remove all attacker access
        steps.append({
            "action": "Comprehensive credential rotation",
            "timeframe": "1-2 hours",
            "details": "Rotate all potentially compromised credentials and API keys",
            "commands": [
                "Rotate all IAM user access keys",
                "Regenerate EC2 instance role credentials",
                "Update application secrets and API keys"
            ]
        })

        # System hardening
        steps.append({
            "action": "Patch vulnerabilities",
            "timeframe": "2-4 hours",
            "details": "Remediate security misconfigurations that enabled the attack",
            "commands": [
                "Review and restrict IAM PassRole permissions",
                "Disable privileged container mode",
                "Implement SCPs to prevent privilege escalation"
            ]
        })

        # Malware removal
        if ioc_data.get("iocs", {}).get("command_lines"):
            steps.append({
                "action": "Remove malicious payloads",
                "timeframe": "1-2 hours",
                "details": "Remove cryptominers, backdoors, and malicious code",
                "commands": [
                    "Scan filesystems for malware",
                    "Remove malicious processes",
                    "Rebuild compromised systems from clean images"
                ]
            })

        return steps

    def _generate_recovery_steps(
        self,
        session: CorrelationSession
    ) -> List[Dict[str, str]]:
        """Generate recovery steps (4-24 hours)."""
        steps = [
            {
                "action": "Restore services",
                "timeframe": "4-8 hours",
                "details": "Gradually restore services with enhanced monitoring",
                "steps": [
                    "Deploy from clean images",
                    "Restore data from verified backups",
                    "Implement enhanced logging and monitoring"
                ]
            },
            {
                "action": "Verify system integrity",
                "timeframe": "8-12 hours",
                "details": "Comprehensive security verification before full restoration",
                "steps": [
                    "Run security scans on all systems",
                    "Verify no backdoors remain",
                    "Test authentication and authorization"
                ]
            },
            {
                "action": "Resume normal operations",
                "timeframe": "12-24 hours",
                "details": "Return to normal operations with enhanced monitoring",
                "steps": [
                    "Gradual traffic restoration",
                    "Continuous monitoring for 48-72 hours",
                    "Document all changes made during IR"
                ]
            }
        ]

        return steps

    def _generate_lessons_learned(
        self,
        session: CorrelationSession,
        mitre_data: Dict[str, Any]
    ) -> List[str]:
        """Generate lessons learned and improvements."""
        lessons = []

        techniques = mitre_data.get("technique_ids", [])

        if "T1548.005" in techniques:
            lessons.append(
                "Implement least privilege for IAM PassRole permissions. "
                "Review and restrict which roles can be passed to which services."
            )

        if "T1110.004" in techniques:
            lessons.append(
                "Implement rate limiting and CAPTCHA on authentication endpoints. "
                "Enable MFA for all user accounts."
            )

        if "T1611" in techniques:
            lessons.append(
                "Disable privileged container mode unless absolutely required. "
                "Implement container runtime security monitoring."
            )

        if "T1087.004" in techniques:
            lessons.append(
                "Implement anomaly detection for IAM enumeration activities. "
                "Alert on unusual patterns of List*/Get* API calls."
            )

        # General lessons
        lessons.extend([
            "Enhance CloudTrail logging to capture all management events",
            "Implement automated response for high-severity alerts",
            "Conduct tabletop exercises for similar attack scenarios",
            "Review and update incident response playbooks",
        ])

        return lessons

    def _estimate_response_timeline(
        self,
        session: CorrelationSession
    ) -> Dict[str, str]:
        """Estimate incident response timeline."""
        severity = "critical" if session.risk_score >= 0.7 else "high"

        if severity == "critical":
            return {
                "immediate_response": "0-15 minutes",
                "containment": "15 minutes - 1 hour",
                "eradication": "1-4 hours",
                "recovery": "4-24 hours",
                "total_estimated_time": "24-48 hours",
                "monitoring_period": "7-14 days post-incident"
            }
        else:
            return {
                "immediate_response": "0-30 minutes",
                "containment": "30 minutes - 2 hours",
                "eradication": "2-8 hours",
                "recovery": "8-48 hours",
                "total_estimated_time": "48-72 hours",
                "monitoring_period": "7 days post-incident"
            }
