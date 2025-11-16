# AI Threat Hunting Simulator

**A production-grade synthetic lab for AI-assisted threat hunting on cloud telemetry**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## Overview

The AI Threat Hunting Simulator is a comprehensive, open-source platform designed to help security professionals, threat hunters, and researchers practice and develop AI-assisted threat detection capabilities in a safe, synthetic environment. It generates realistic cloud attack telemetry, simulates sophisticated multi-stage attacks, and provides an AI-powered analysis engine that correlates events, maps them to MITRE ATT&CK techniques, and generates actionable threat intelligence.

## Motivation

Modern cloud environments generate massive volumes of telemetry data across multiple services—audit logs, network flows, container events, IAM changes, and API access logs. Identifying sophisticated attacks within this noise requires:

- **Advanced correlation** across disparate data sources
- **Pattern recognition** that spans hours or days
- **Contextual understanding** of normal vs. anomalous behavior
- **Rapid response planning** based on attack stage and impact

Traditional SIEM tools struggle with context and narrative generation. AI-assisted threat hunting represents the next evolution, but practicing these techniques on production data carries risks. This simulator provides:

✅ **Safe experimentation** with realistic but synthetic data
✅ **Reproducible scenarios** for training and benchmarking
✅ **Educational framework** for understanding attack patterns
✅ **Reference implementation** for AI-assisted security workflows

## Features

### 🎯 Realistic Attack Scenarios

- **Credential Stuffing** - Automated credential attacks against cloud APIs
- **Container Breakout** - Escape attempts from containerized workloads
- **Lateral Movement** - Multi-hop pivoting through cloud resources
- **IAM Privilege Escalation** - Abuse of identity and access management
- **API Key Theft & Misuse** - Exfiltration and unauthorized API usage
- **Persistence Mechanisms** - Hidden roles, scheduled tasks, backdoor accounts

### 🔬 Synthetic Telemetry Generator

- CloudTrail-like audit logs
- VPC flow logs (network traffic)
- Container/workload execution logs
- API Gateway access logs
- IAM role and permission change events
- Configurable cloud topologies (single-account, multi-account hub-spoke)

### 🤖 AI-Assisted Analysis Engine

- **Event Correlation** - Groups related events into attack sessions
- **Kill Chain Mapping** - Maps events to Lockheed Martin Cyber Kill Chain stages
- **MITRE ATT&CK Integration** - Automatic technique tagging (T1078, T1548, etc.)
- **IOC Extraction** - Identifies IPs, user agents, API keys, compromised identities
- **Threat Narrative Generation** - Creates human-readable attack stories
- **Automated Response Planning** - Suggests containment and remediation steps

### 📊 SOC Dashboard UI

- Timeline visualization of attack progression
- Attack graph showing entity relationships
- MITRE ATT&CK technique coverage heatmap
- IOC tables with context
- Narrative panel with AI-generated explanations
- Response plan recommendations

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     AI Threat Hunting Simulator                  │
└─────────────────────────────────────────────────────────────────┘

┌──────────────────┐      ┌──────────────────┐      ┌─────────────┐
│   GENERATOR      │─────▶│ ANALYSIS ENGINE  │─────▶│  SOC DASHBOARD
│                  │      │                  │      │     (UI)     │
│ • Attack Traces  │      │ • Correlation    │      │              │
│ • Telemetry      │      │ • Kill Chain     │      │ • Timeline   │
│ • Topologies     │      │ • MITRE Mapping  │      │ • Graph View │
│ • Scenarios      │      │ • AI Agents      │      │ • Narrative  │
└──────────────────┘      └──────────────────┘      └─────────────┘
         │                         │
         │                         │
         ▼                         ▼
    [JSONL Logs]            [Analysis Reports]
         │                         │
         └────────┬────────────────┘
                  │
                  ▼
           ┌─────────────┐
           │     CLI     │
           │             │
           │ • Run       │
           │ • Validate  │
           │ • Report    │
           └─────────────┘
```

## Quick Start

### Prerequisites

- **Docker** and **Docker Compose** (for containerized deployment)
- **Python 3.11+** (for local development)
- **Node.js 18+** (for UI development)

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/yourusername/ai-threat-hunting-simulator.git
cd ai-threat-hunting-simulator
```

2. **Set up environment:**

```bash
cp .env.example .env
# Edit .env if needed (defaults work for most cases)
```

3. **Start with Docker Compose:**

```bash
docker-compose up --build
```

This will start:
- Analysis Engine API on `http://localhost:8000`
- SOC Dashboard UI on `http://localhost:3000`

### Running Your First Scenario

**Using the CLI:**

```bash
# Install Python dependencies
pip install -r requirements.txt

# Run a scenario (generates telemetry + analysis)
python cli/run_scenario.py --scenario iam_priv_escalation --output ./output/iam_escalation_demo

# View the generated files
ls -la ./output/iam_escalation_demo/
```

**Output includes:**
- `telemetry.jsonl` - Raw synthetic logs
- `analysis_report.json` - Structured analysis results
- `analysis_report.md` - Human-readable narrative
- `iocs.json` - Extracted indicators of compromise

### Viewing in the SOC Dashboard

1. Open browser to `http://localhost:3000`
2. Click "Load Scenario" and select "IAM Privilege Escalation"
3. Explore the timeline, attack graph, and AI-generated narrative

## Example Walkthrough: IAM Privilege Escalation

This scenario simulates an attacker who:

1. **Reconnaissance** - Enumerates IAM roles and policies
2. **Initial Access** - Uses compromised credentials for a low-privilege service account
3. **Privilege Escalation** - Exploits `iam:PassRole` + `lambda:CreateFunction` to escalate
4. **Persistence** - Creates a backdoor admin role
5. **Impact** - Accesses sensitive S3 buckets

**Running the scenario:**

```bash
python cli/run_scenario.py --scenario iam_priv_escalation --output ./demo
```

**Generated telemetry includes:**

```json
{"timestamp": "2025-11-16T10:23:45Z", "event_type": "iam.list_roles", "principal": "arn:aws:iam::123456789012:user/service-account-readonly", "source_ip": "203.0.113.42", ...}
{"timestamp": "2025-11-16T10:24:12Z", "event_type": "iam.get_role_policy", "principal": "arn:aws:iam::123456789012:user/service-account-readonly", ...}
{"timestamp": "2025-11-16T10:25:33Z", "event_type": "lambda.create_function", "principal": "arn:aws:iam::123456789012:user/service-account-readonly", "metadata": {"role_arn": "arn:aws:iam::123456789012:role/HighPrivilegeRole"}, ...}
```

**Analysis output:**

```markdown
## Threat Analysis Report

**Scenario:** IAM Privilege Escalation
**Attack Duration:** 47 minutes
**Severity:** CRITICAL

### Executive Summary
An attacker leveraged compromised low-privilege credentials to enumerate IAM
resources, then exploited a misconfigured iam:PassRole permission combined with
lambda:CreateFunction to assume high-privilege roles. The attacker established
persistence via a backdoor administrative role.

### Kill Chain Stages Detected
- [x] Reconnaissance (IAM enumeration)
- [x] Privilege Escalation (PassRole abuse)
- [x] Persistence (Backdoor role creation)
- [x] Impact (S3 data access)

### MITRE ATT&CK Techniques
- T1078.004 - Valid Accounts: Cloud Accounts
- T1548.005 - Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access
- T1136.003 - Create Account: Cloud Account
...
```

## Extensibility

### Adding New Attack Scenarios

1. Create a new directory in `generator/attack_traces/<scenario_name>/`
2. Add a `scenario.yaml` defining the attack chain:

```yaml
name: "My Custom Attack"
description: "..."
stages:
  - stage: "initial_access"
    events:
      - type: "api.login"
        count: 1
        ...
```

3. Implement scenario logic in `generator/attack_traces/<scenario_name>/generator.py`

### Extending the Analysis Engine

**Adding a new agent:**

```python
# analysis_engine/agents/my_custom_agent.py
from typing import List, Dict

class MyCustomAgent:
    def analyze(self, events: List[Dict]) -> Dict:
        """Your custom analysis logic"""
        return {"findings": [...]}
```

**Integrating with main pipeline:**

```python
# In analysis_engine/core/pipeline.py
from agents.my_custom_agent import MyCustomAgent

custom_agent = MyCustomAgent()
results = custom_agent.analyze(events)
```

### Plugging in a Real LLM

The analysis engine is designed to support real LLM integration. Look for `# LLM_INTEGRATION_POINT` comments in:

- `analysis_engine/agents/threat_narrative_agent.py`
- `analysis_engine/agents/response_planner_agent.py`

To integrate (example with OpenAI):

```python
# Replace template-based generation with:
import openai

def generate_narrative(self, context: Dict) -> str:
    # LLM_INTEGRATION_POINT - Replace with real LLM call
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a threat hunting analyst..."},
            {"role": "user", "content": f"Analyze this attack: {context}"}
        ]
    )
    return response.choices[0].message.content
```

## Project Structure

```
ai-threat-hunting-simulator/
├── README.md
├── LICENSE
├── docker-compose.yml
├── .env.example
├── requirements.txt
├── generator/              # Synthetic telemetry generation
│   ├── attack_traces/      # Attack scenario definitions
│   ├── cloud_topologies/   # Simulated cloud environments
│   ├── schemas/            # Data schemas
│   └── telemetry_synthesizer.py
├── analysis_engine/        # AI-assisted analysis pipeline
│   ├── core/               # Correlation, parsing, mapping
│   ├── agents/             # AI agents (narrative, IOC, response)
│   ├── explainers/         # Narrative builders
│   ├── reports/            # Report generators
│   └── api/                # HTTP API
├── ui/                     # SOC Dashboard (React)
│   └── soc_dashboard/
├── cli/                    # Command-line tools
│   ├── run_scenario.py
│   └── validate_traces.py
├── docs/                   # Documentation
├── notebooks/              # Jupyter notebooks
├── tests/                  # Unit tests
└── scripts/                # Utility scripts
```

## Safety & Ethics

⚠️ **IMPORTANT**: This simulator is designed exclusively for:

- **Education and training** of security professionals
- **Security research** in controlled environments
- **Development and testing** of threat detection systems
- **Red team / blue team exercises** with proper authorization

All data generated by this system is **synthetic and fictitious**. It contains:
- No real customer data
- No real credentials or secrets
- No real IP addresses or infrastructure details

**This is NOT an offensive security tool.** Do not use generated attack patterns against systems you don't own or have explicit authorization to test.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas of interest:
- Additional attack scenarios
- Enhanced visualizations
- Real-world telemetry format compatibility
- Performance optimizations
- Integration with threat intelligence feeds

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- MITRE ATT&CK® framework
- Lockheed Martin Cyber Kill Chain
- Cloud security community and researchers
- Open-source threat hunting tools and projects

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/ai-threat-hunting-simulator/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/ai-threat-hunting-simulator/discussions)

---

**Built for the security community, by security practitioners.**
