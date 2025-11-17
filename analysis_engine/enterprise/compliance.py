"""Compliance reporting framework for enterprise deployments."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

class ComplianceStandard(str, Enum):
    """Supported compliance standards."""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_csf"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    CCPA = "ccpa"
    FedRAMP = "fedramp"

class ControlStatus(str, Enum):
    """Compliance control status."""
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"

@dataclass
class ComplianceControl:
    """Individual compliance control."""
    control_id: str
    standard: ComplianceStandard
    title: str
    description: str
    requirements: List[str]
    status: ControlStatus
    evidence: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    last_assessed: Optional[datetime] = None
    next_review: Optional[datetime] = None

@dataclass
class ComplianceReport:
    """Compliance assessment report."""
    report_id: str
    standard: ComplianceStandard
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    assessed_by: str
    controls_total: int
    controls_implemented: int
    controls_partial: int
    controls_not_implemented: int
    compliance_score: float
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

class ComplianceFramework:
    """Enterprise compliance reporting framework."""

    def __init__(self):
        self.controls: Dict[str, List[ComplianceControl]] = {}
        self._load_standard_controls()

    def _load_standard_controls(self):
        """Load compliance controls for various standards."""
        self.controls[ComplianceStandard.SOC2.value] = self._load_soc2_controls()
        self.controls[ComplianceStandard.ISO27001.value] = self._load_iso27001_controls()
        self.controls[ComplianceStandard.NIST_CSF.value] = self._load_nist_csf_controls()
        self.controls[ComplianceStandard.GDPR.value] = self._load_gdpr_controls()

    def _load_soc2_controls(self) -> List[ComplianceControl]:
        """Load SOC 2 Trust Services Criteria controls."""
        return [
            ComplianceControl(
                control_id="CC6.1",
                standard=ComplianceStandard.SOC2,
                title="Logical and Physical Access Controls",
                description="The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
                requirements=[
                    "Implement authentication mechanisms",
                    "Enforce role-based access controls",
                    "Log and monitor access attempts",
                    "Review access logs regularly"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "SSO/SAML authentication implemented",
                    "RBAC system in place",
                    "Audit logging enabled",
                    "Monthly access reviews"
                ]
            ),
            ComplianceControl(
                control_id="CC7.2",
                standard=ComplianceStandard.SOC2,
                title="Detection of Security Events",
                description="The entity implements detection policies, procedures, and tools to identify anomalies.",
                requirements=[
                    "Deploy intrusion detection systems",
                    "Implement anomaly detection",
                    "Monitor for security events",
                    "Alert on suspicious activities"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "ML-based anomaly detection deployed",
                    "Real-time threat detection rules",
                    "SIEM integration configured",
                    "24/7 monitoring alerts"
                ]
            ),
            ComplianceControl(
                control_id="CC7.3",
                standard=ComplianceStandard.SOC2,
                title="Response to Security Incidents",
                description="The entity responds to identified security incidents.",
                requirements=[
                    "Incident response plan documented",
                    "Incident classification procedures",
                    "Response team designated",
                    "Post-incident analysis conducted"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "IR playbooks available",
                    "Purple team exercises conducted",
                    "Incident response team trained",
                    "Post-mortem reports generated"
                ]
            ),
            ComplianceControl(
                control_id="CC8.1",
                standard=ComplianceStandard.SOC2,
                title="Change Management",
                description="The entity authorizes, designs, develops, and maintains system changes.",
                requirements=[
                    "Change approval process",
                    "Testing before deployment",
                    "Change documentation",
                    "Rollback procedures"
                ],
                status=ControlStatus.PARTIAL,
                evidence=[
                    "Code review process",
                    "Automated testing"
                ],
                notes="Need to implement formal change approval workflow"
            ),
            ComplianceControl(
                control_id="A1.2",
                standard=ComplianceStandard.SOC2,
                title="Confidentiality - Data Classification",
                description="The entity classifies data based on confidentiality requirements.",
                requirements=[
                    "Data classification policy",
                    "Labeling of sensitive data",
                    "Access controls based on classification",
                    "Encryption of confidential data"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "Multi-tenancy data isolation",
                    "Encryption at rest and in transit",
                    "Access controls per tenant"
                ]
            )
        ]

    def _load_iso27001_controls(self) -> List[ComplianceControl]:
        """Load ISO 27001 controls."""
        return [
            ComplianceControl(
                control_id="A.9.1.1",
                standard=ComplianceStandard.ISO27001,
                title="Access Control Policy",
                description="An access control policy shall be established, documented and reviewed.",
                requirements=[
                    "Document access control policy",
                    "Define roles and responsibilities",
                    "Review policy annually",
                    "Communicate to all users"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "RBAC policy documented",
                    "Annual policy review",
                    "User training completed"
                ]
            ),
            ComplianceControl(
                control_id="A.12.4.1",
                standard=ComplianceStandard.ISO27001,
                title="Event Logging",
                description="Event logs recording user activities, exceptions, and information security events shall be produced and kept.",
                requirements=[
                    "Log security events",
                    "Include timestamps and user IDs",
                    "Protect log integrity",
                    "Retain logs per policy"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "Comprehensive audit logging",
                    "Tamper-evident log chain",
                    "Log retention for 1 year",
                    "Hash-based integrity verification"
                ]
            ),
            ComplianceControl(
                control_id="A.12.6.1",
                standard=ComplianceStandard.ISO27001,
                title="Management of Technical Vulnerabilities",
                description="Information about technical vulnerabilities shall be obtained in a timely fashion.",
                requirements=[
                    "Vulnerability scanning",
                    "Patch management process",
                    "Track and remediate vulnerabilities",
                    "Regular security assessments"
                ],
                status=ControlStatus.PARTIAL,
                evidence=[
                    "Dependency scanning enabled"
                ],
                notes="Need automated vulnerability scanning"
            ),
            ComplianceControl(
                control_id="A.16.1.5",
                standard=ComplianceStandard.ISO27001,
                title="Response to Information Security Incidents",
                description="Information security incidents shall be responded to in accordance with documented procedures.",
                requirements=[
                    "Incident response procedures",
                    "Incident classification",
                    "Escalation procedures",
                    "Evidence collection"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "IR procedures documented",
                    "Purple team exercises",
                    "Incident tracking system"
                ]
            ),
            ComplianceControl(
                control_id="A.18.1.5",
                standard=ComplianceStandard.ISO27001,
                title="Regulation of Cryptographic Controls",
                description="Cryptographic controls shall be used in compliance with relevant agreements, legislation and regulations.",
                requirements=[
                    "Encryption policy",
                    "Key management procedures",
                    "Approved algorithms only",
                    "Regular cryptographic review"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "TLS 1.3 for data in transit",
                    "AES-256 for data at rest",
                    "Key rotation procedures"
                ]
            )
        ]

    def _load_nist_csf_controls(self) -> List[ComplianceControl]:
        """Load NIST Cybersecurity Framework controls."""
        return [
            ComplianceControl(
                control_id="ID.AM-1",
                standard=ComplianceStandard.NIST_CSF,
                title="Asset Management",
                description="Physical devices and systems within the organization are inventoried.",
                requirements=[
                    "Maintain asset inventory",
                    "Track hardware and software",
                    "Regular inventory updates",
                    "Asset classification"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "Cloud resource tracking",
                    "Multi-cloud asset discovery",
                    "Automated inventory updates"
                ]
            ),
            ComplianceControl(
                control_id="PR.AC-1",
                standard=ComplianceStandard.NIST_CSF,
                title="Access Control",
                description="Identities and credentials are issued, managed, verified, revoked for authorized devices, users and processes.",
                requirements=[
                    "Identity management system",
                    "Credential lifecycle management",
                    "Access reviews",
                    "Privileged access management"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "SSO/SAML integration",
                    "Quarterly access reviews",
                    "MFA enforcement"
                ]
            ),
            ComplianceControl(
                control_id="DE.AE-1",
                standard=ComplianceStandard.NIST_CSF,
                title="Anomaly Detection",
                description="A baseline of network operations and expected data flows is established and managed.",
                requirements=[
                    "Establish baselines",
                    "Detect deviations",
                    "Alert on anomalies",
                    "Regular baseline updates"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "Behavioral baseline learning",
                    "ML anomaly detection",
                    "Real-time anomaly alerts",
                    "Weekly baseline updates"
                ]
            ),
            ComplianceControl(
                control_id="RS.AN-1",
                standard=ComplianceStandard.NIST_CSF,
                title="Incident Analysis",
                description="Notifications from detection systems are investigated.",
                requirements=[
                    "Investigation procedures",
                    "Alert triage process",
                    "Incident classification",
                    "Root cause analysis"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "Purple team analysis",
                    "Threat hunting capabilities",
                    "MITRE ATT&CK mapping"
                ]
            ),
            ComplianceControl(
                control_id="RC.RP-1",
                standard=ComplianceStandard.NIST_CSF,
                title="Recovery Planning",
                description="Recovery plan is executed during or after a cybersecurity incident.",
                requirements=[
                    "Recovery procedures documented",
                    "Regular testing of recovery",
                    "Recovery time objectives",
                    "Communication plan"
                ],
                status=ControlStatus.PARTIAL,
                evidence=[
                    "Backup procedures",
                    "DR documentation"
                ],
                notes="Need to conduct tabletop exercises"
            )
        ]

    def _load_gdpr_controls(self) -> List[ComplianceControl]:
        """Load GDPR controls."""
        return [
            ComplianceControl(
                control_id="Art.32",
                standard=ComplianceStandard.GDPR,
                title="Security of Processing",
                description="Implement appropriate technical and organizational measures to ensure security.",
                requirements=[
                    "Encryption of personal data",
                    "Pseudonymization where possible",
                    "Ensure confidentiality and integrity",
                    "Regular security testing"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "Data encryption",
                    "Multi-tenancy isolation",
                    "Regular security assessments"
                ]
            ),
            ComplianceControl(
                control_id="Art.33",
                standard=ComplianceStandard.GDPR,
                title="Data Breach Notification",
                description="Notify supervisory authority of personal data breach within 72 hours.",
                requirements=[
                    "Breach detection mechanisms",
                    "Notification procedures",
                    "Breach documentation",
                    "Timeline compliance"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "Real-time breach detection",
                    "Automated alerting",
                    "Incident response procedures"
                ]
            ),
            ComplianceControl(
                control_id="Art.30",
                standard=ComplianceStandard.GDPR,
                title="Records of Processing Activities",
                description="Maintain records of processing activities under your responsibility.",
                requirements=[
                    "Document processing activities",
                    "Record purposes of processing",
                    "Data retention periods",
                    "Security measures"
                ],
                status=ControlStatus.IMPLEMENTED,
                evidence=[
                    "Comprehensive audit logging",
                    "Data processing inventory",
                    "Retention policies"
                ]
            )
        ]

    def assess_compliance(
        self,
        standard: ComplianceStandard,
        assessed_by: str,
        period_start: datetime,
        period_end: datetime
    ) -> ComplianceReport:
        """Generate compliance assessment report.

        Args:
            standard: Compliance standard to assess
            assessed_by: Assessor name
            period_start: Assessment period start
            period_end: Assessment period end

        Returns:
            Compliance report
        """
        controls = self.controls.get(standard.value, [])

        # Count control statuses
        implemented = sum(1 for c in controls if c.status == ControlStatus.IMPLEMENTED)
        partial = sum(1 for c in controls if c.status == ControlStatus.PARTIAL)
        not_implemented = sum(1 for c in controls if c.status == ControlStatus.NOT_IMPLEMENTED)
        total = len([c for c in controls if c.status != ControlStatus.NOT_APPLICABLE])

        # Calculate compliance score (weighted: full=1.0, partial=0.5, none=0.0)
        score = (implemented + (partial * 0.5)) / total if total > 0 else 0.0

        # Generate findings
        findings = []
        recommendations = []

        for control in controls:
            if control.status == ControlStatus.NOT_IMPLEMENTED:
                findings.append({
                    "control_id": control.control_id,
                    "title": control.title,
                    "severity": "high",
                    "description": f"Control not implemented: {control.description}",
                    "recommendation": f"Implement {control.control_id}: {control.title}"
                })
                recommendations.append(f"Implement {control.control_id}: {control.title}")

            elif control.status == ControlStatus.PARTIAL:
                findings.append({
                    "control_id": control.control_id,
                    "title": control.title,
                    "severity": "medium",
                    "description": f"Partial implementation: {control.notes or 'See requirements'}",
                    "recommendation": f"Complete implementation of {control.control_id}"
                })
                recommendations.append(f"Complete {control.control_id}: {control.notes}")

        report = ComplianceReport(
            report_id=f"compliance-{standard.value}-{datetime.now().strftime('%Y%m%d')}",
            standard=standard,
            generated_at=datetime.now(),
            period_start=period_start,
            period_end=period_end,
            assessed_by=assessed_by,
            controls_total=total,
            controls_implemented=implemented,
            controls_partial=partial,
            controls_not_implemented=not_implemented,
            compliance_score=score * 100,  # Convert to percentage
            findings=findings,
            recommendations=recommendations
        )

        return report

    def get_control_details(
        self,
        standard: ComplianceStandard,
        control_id: str
    ) -> Optional[ComplianceControl]:
        """Get details of specific control.

        Args:
            standard: Compliance standard
            control_id: Control identifier

        Returns:
            Control details if found
        """
        controls = self.controls.get(standard.value, [])
        for control in controls:
            if control.control_id == control_id:
                return control
        return None

    def update_control_status(
        self,
        standard: ComplianceStandard,
        control_id: str,
        status: ControlStatus,
        evidence: Optional[List[str]] = None,
        notes: Optional[str] = None
    ) -> bool:
        """Update control implementation status.

        Args:
            standard: Compliance standard
            control_id: Control to update
            status: New status
            evidence: Supporting evidence
            notes: Additional notes

        Returns:
            True if updated successfully
        """
        controls = self.controls.get(standard.value, [])
        for control in controls:
            if control.control_id == control_id:
                control.status = status
                if evidence:
                    control.evidence.extend(evidence)
                if notes:
                    control.notes = notes
                control.last_assessed = datetime.now()
                control.next_review = datetime.now() + timedelta(days=90)
                return True
        return False

    def get_compliance_dashboard(self) -> Dict[str, Any]:
        """Get compliance overview dashboard.

        Returns:
            Dashboard data with all standards
        """
        dashboard = {}

        for standard_value, controls in self.controls.items():
            total = len([c for c in controls if c.status != ControlStatus.NOT_APPLICABLE])
            implemented = sum(1 for c in controls if c.status == ControlStatus.IMPLEMENTED)
            partial = sum(1 for c in controls if c.status == ControlStatus.PARTIAL)

            score = (implemented + (partial * 0.5)) / total if total > 0 else 0.0

            dashboard[standard_value] = {
                "total_controls": total,
                "implemented": implemented,
                "partial": partial,
                "not_implemented": sum(1 for c in controls if c.status == ControlStatus.NOT_IMPLEMENTED),
                "compliance_score": round(score * 100, 1),
                "status": "compliant" if score >= 0.9 else "partial" if score >= 0.7 else "non-compliant"
            }

        return dashboard
