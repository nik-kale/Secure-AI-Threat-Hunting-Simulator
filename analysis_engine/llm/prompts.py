"""
Optimized prompts for LLM-powered threat analysis.
"""

# Threat Narrative Generation Prompt
THREAT_NARRATIVE_PROMPT = """
Analyze the following cloud security incident and generate a comprehensive threat narrative.

## Session Information
{session_data}

## Kill Chain Analysis
{kill_chain_data}

## MITRE ATT&CK Mapping
{mitre_data}

## Indicators of Compromise
{ioc_data}

## Task
Generate a detailed threat narrative with the following sections:

### 1. Executive Summary
- Concise overview of the attack (2-3 paragraphs)
- Primary attack type and objectives
- Overall risk assessment and severity
- Key findings and impacts

### 2. Attack Timeline
- Chronological progression of the attack
- Key events at each stage of the kill chain
- Timing and sequence of activities
- Pivotal moments in the attack progression

### 3. Detailed Technical Analysis
- In-depth analysis of attacker techniques
- Explanation of each MITRE ATT&CK technique observed
- Technical details of exploitation methods
- Attack infrastructure and tools used
- Correlation between different attack stages

### 4. Impact Assessment
- Compromised accounts and resources
- Data accessed or exfiltrated
- Systems affected
- Business impact and potential damages
- Compliance and regulatory implications

### 5. Recommended Actions
- Immediate containment steps (prioritized)
- Eradication procedures
- Recovery recommendations
- Long-term security improvements
- Preventive measures for similar attacks

Please provide a clear, well-structured narrative that would be suitable for both technical security teams and executive stakeholders. Use professional security terminology and be specific about threats and impacts.
"""

# IOC Extraction Prompt
IOC_EXTRACTION_PROMPT = """
Analyze the following security events and extract all indicators of compromise (IOCs).

## Events to Analyze
{events}

Total events in session: {total_events}

## Task
Extract and categorize all IOCs from the events. For each IOC category, provide:

1. **IP Addresses**
   - Source IPs involved in suspicious activities
   - Distinguish between external attackers and internal compromised hosts
   - Note any IPs with known malicious reputation

2. **Compromised Accounts/Principals**
   - User accounts showing suspicious behavior
   - Service accounts or roles misused
   - Privilege level of each compromised account

3. **Targeted Resources**
   - AWS resources accessed or modified
   - Sensitive data repositories targeted
   - Infrastructure components affected

4. **Suspicious Commands**
   - Command-line executions
   - Scripts or payloads deployed
   - Container escape or privilege escalation commands

5. **API Keys and Credentials**
   - Exposed or stolen credentials
   - API keys used inappropriately
   - Authentication tokens compromised

6. **Network Indicators**
   - Suspicious domains contacted
   - Unusual network traffic patterns
   - Command-and-control infrastructure

7. **File Hashes and Malware**
   - Any malicious files or payloads
   - Cryptominers or backdoors
   - Persistence mechanisms

## Severity Classification
For each IOC, assign a severity level:
- **CRITICAL**: Immediate security risk (exposed secrets, active malware, admin account compromise)
- **HIGH**: Significant security concern (compromised user accounts, suspicious commands)
- **MEDIUM**: Notable indicators requiring investigation (unusual access patterns)
- **LOW**: Minor anomalies or suspicious but potentially legitimate activities

## Output Format
Provide a structured analysis with:
- Clear categorization of IOCs
- Severity assessment for each
- Context and explanation of why each is significant
- Relationships between IOCs (e.g., same source IP across multiple events)
- Recommendations for IOC handling (block, monitor, investigate)

Be thorough and identify all potential IOCs, even if some may require further investigation to confirm malicious intent.
"""

# Response Planning Prompt
RESPONSE_PLANNING_PROMPT = """
Based on the following cloud security incident analysis, generate a comprehensive incident response plan.

## Session Information
{session_data}

## MITRE ATT&CK Techniques Identified
{mitre_data}

## Indicators of Compromise
{ioc_data}

## Threat Narrative Summary
{narrative_summary}

## Task
Create a detailed incident response plan following the NIST incident response lifecycle. Structure your plan with:

### 1. Immediate Actions (0-15 minutes)
- **Triage and Assessment**
  - Initial severity confirmation
  - Scope determination
  - Stakeholder notification

- **Critical Containment**
  - Disable compromised credentials immediately
  - Block malicious IPs at network perimeter
  - Isolate affected systems
  - Preserve forensic evidence

For each action, specify:
- Priority level (CRITICAL/HIGH/MEDIUM)
- Exact timeframe
- Specific AWS CLI commands or procedures
- Expected outcome

### 2. Containment Phase (15 minutes - 2 hours)
- **Short-term containment**
  - Network isolation procedures
  - Access revocation steps
  - Service disruption mitigation

- **Evidence preservation**
  - Log collection and backup
  - System snapshots
  - Memory dumps if applicable

### 3. Eradication Phase (2-8 hours)
- **Remove attacker presence**
  - Delete backdoor accounts/roles
  - Remove malicious Lambda functions
  - Terminate compromised containers
  - Clean up persistence mechanisms

- **Vulnerability remediation**
  - Patch exploited vulnerabilities
  - Fix misconfigurations
  - Update security policies

### 4. Recovery Phase (8-48 hours)
- **System restoration**
  - Rebuild compromised systems from clean images
  - Restore from verified backups
  - Gradual service restoration

- **Validation**
  - Security verification before production
  - Monitoring for reinfection
  - Performance and functionality testing

### 5. Post-Incident Activities
- **Lessons Learned**
  - Root cause analysis
  - Security control improvements
  - Process enhancements
  - Training needs identified

- **Long-term Security Improvements**
  - Architecture changes
  - Detective control enhancements
  - Preventive measures
  - Monitoring and alerting improvements

### 6. Timeline Estimate
Provide realistic time estimates for:
- Each phase of response
- Total incident resolution time
- Extended monitoring period

### 7. Resource Requirements
- Team members needed (roles and skills)
- Tools and access required
- External support (forensics, legal, vendors)

### 8. Communication Plan
- Internal stakeholders to notify
- Reporting requirements (legal, regulatory)
- Customer communication (if applicable)
- Public disclosure considerations

Provide specific, actionable guidance that can be immediately executed by an incident response team. Include actual AWS CLI commands where applicable, and prioritize actions by criticality and time sensitivity.
"""

# MITRE Technique Identification Prompt
MITRE_IDENTIFICATION_PROMPT = """
Analyze the following security events and identify all applicable MITRE ATT&CK techniques.

## Events to Analyze
{events}

## Task
For each security event or pattern of events, identify:

1. **MITRE ATT&CK Technique IDs** (e.g., T1078.004, T1548.005)
2. **Tactic Category** (e.g., Privilege Escalation, Defense Evasion, Impact)
3. **Technique Name** and brief description
4. **Evidence** from the events that supports this classification
5. **Confidence Level** (High/Medium/Low) based on available evidence

## Focus Areas for Cloud Environments

### Initial Access (TA0001)
- Valid Accounts (T1078)
  - T1078.004: Cloud Accounts
- Exploit Public-Facing Application (T1190)

### Execution (TA0002)
- User Execution (T1204)
- Serverless Execution (T1648)

### Persistence (TA0003)
- Create Account (T1136)
  - T1136.003: Cloud Account
- Valid Accounts (T1078)

### Privilege Escalation (TA0004)
- Valid Accounts (T1078)
- Abuse Elevation Control Mechanism (T1548)
  - T1548.005: Temporary Elevated Cloud Access

### Defense Evasion (TA0005)
- Impair Defenses (T1562)
  - T1562.008: Disable Cloud Logs
- Modify Cloud Compute Infrastructure (T1578)

### Credential Access (TA0006)
- Brute Force (T1110)
  - T1110.004: Credential Stuffing
- Unsecured Credentials (T1552)

### Discovery (TA0007)
- Cloud Infrastructure Discovery (T1580)
- Account Discovery (T1087)
  - T1087.004: Cloud Account
- Permission Groups Discovery (T1069)

### Lateral Movement (TA0008)
- Use Alternate Authentication Material (T1550)

### Collection (TA0009)
- Data from Cloud Storage Object (T1530)

### Impact (TA0040)
- Resource Hijacking (T1496)
- Data Destruction (T1485)
- Service Stop (T1489)

### Container-Specific
- Escape to Host (T1611)

## Output Format
List all identified techniques in the following format:

**T####.###: Technique Name**
- Tactic: [Tactic Category]
- Confidence: [High/Medium/Low]
- Evidence: [Specific events or patterns supporting this classification]
- Impact: [Brief description of impact in this context]

Focus on cloud-native techniques, especially those targeting AWS, containers, and serverless environments. Be specific and provide clear evidence for each technique identified.
"""

# Alternative short-form prompts for faster analysis

QUICK_NARRATIVE_PROMPT = """
Provide a concise threat narrative (3-5 paragraphs) covering:
1. What happened (attack overview)
2. How it happened (techniques used)
3. Impact and affected resources
4. Key recommendations

Session: {session_data}
Techniques: {mitre_data}
IOCs: {ioc_data}
"""

QUICK_IOC_PROMPT = """
Extract all IOCs from these events and categorize by type (IPs, accounts, commands, etc.).
Focus on high-severity indicators.

{events}
"""

QUICK_RESPONSE_PROMPT = """
Generate immediate response actions (next 1-2 hours) for this incident:
1. Critical actions (0-15 min)
2. Containment steps (15-60 min)
3. Top 3 priorities

Incident: {narrative_summary}
IOCs: {ioc_data}
"""

# Prompt templates for different analysis modes
PROMPTS = {
    "narrative": {
        "detailed": THREAT_NARRATIVE_PROMPT,
        "quick": QUICK_NARRATIVE_PROMPT,
    },
    "ioc_extraction": {
        "detailed": IOC_EXTRACTION_PROMPT,
        "quick": QUICK_IOC_PROMPT,
    },
    "response_planning": {
        "detailed": RESPONSE_PLANNING_PROMPT,
        "quick": QUICK_RESPONSE_PROMPT,
    },
    "mitre_identification": {
        "detailed": MITRE_IDENTIFICATION_PROMPT,
    }
}


def get_prompt(prompt_type: str, mode: str = "detailed") -> str:
    """
    Get a prompt template by type and mode.

    Args:
        prompt_type: Type of prompt (narrative, ioc_extraction, response_planning, mitre_identification)
        mode: Mode of analysis (detailed or quick)

    Returns:
        Prompt template string

    Raises:
        ValueError: If prompt_type or mode is invalid
    """
    if prompt_type not in PROMPTS:
        raise ValueError(
            f"Unknown prompt type: {prompt_type}. "
            f"Available types: {', '.join(PROMPTS.keys())}"
        )

    prompt_modes = PROMPTS[prompt_type]

    if mode not in prompt_modes:
        # Default to detailed if mode not available
        mode = "detailed"

    return prompt_modes[mode]
