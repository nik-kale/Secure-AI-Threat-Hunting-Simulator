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

### 🤖 AI-Powered Analysis Engine

- **Event Correlation** - Groups related events into attack sessions using temporal and behavioral analysis
- **Kill Chain Mapping** - Maps events to Lockheed Martin Cyber Kill Chain stages
- **MITRE ATT&CK Integration** - Automatic technique tagging (T1078, T1548, T1611, etc.)
- **IOC Extraction** - Identifies IPs, user agents, API keys, compromised identities with ML-enhanced detection
- **LLM-Powered Threat Narratives** - AI-generated attack stories using GPT-4 or Claude (optional)
- **Threat Intelligence Enrichment** - Real-time IOC enrichment from AbuseIPDB, VirusTotal (optional)
- **Automated Response Planning** - AI-generated containment and remediation playbooks
- **Dual-Mode Operation** - Works with or without LLM/threat intel (graceful fallback to templates)

### 📊 SOC Dashboard UI

- Timeline visualization of attack progression
- Attack graph showing entity relationships
- MITRE ATT&CK technique coverage heatmap
- IOC tables with context
- Narrative panel with AI-generated explanations
- Response plan recommendations

### 🚀 v2.0 Features (New!)

- **Detection Rule Testing Framework** - Validate SIEM rules against synthetic telemetry
  - Sigma rule support with full parsing and matching
  - Precision, recall, F1 score, and accuracy metrics
  - True/false positive/negative analysis
  - Auto-generation of Sigma rules from scenarios
  - Batch rule testing with coverage reports

- **Real-Time Streaming** - WebSocket support for live telemetry and analysis
  - Live scenario generation streaming
  - Real-time analysis progress updates
  - Event batch broadcasting
  - Topic-based pub/sub messaging
  - Connection health monitoring with heartbeats

- **Redis Caching Layer** - Performance optimization through intelligent caching
  - Analysis result caching with configurable TTL
  - Scenario metadata and detection rule caching
  - IOC enrichment caching
  - Batch operations for high throughput
  - Cache statistics and hit rate tracking
  - Automatic serialization (JSON/pickle)

- **Enhanced API Endpoints** - 15+ new endpoints for advanced workflows
  - POST `/detection/test-rule` - Test single Sigma rule
  - POST `/detection/test-rules-batch` - Batch rule testing
  - GET `/detection/rules` - List all Sigma rules
  - POST `/detection/generate-rule` - Auto-generate rules
  - WS `/ws/scenario/{name}` - Stream scenario generation
  - WS `/ws/analysis` - Stream analysis progress
  - WS `/ws/live` - Live telemetry feed
  - GET `/cache/stats` - Cache performance metrics
  - GET `/ws/stats` - WebSocket connection stats

- **Complete Sigma Rule Library** - Production-ready detection rules
  - AWS IAM privilege escalation detection
  - Container escape attempt detection
  - Credential stuffing pattern detection
  - Lateral movement through cloud resources
  - Data exfiltration from cloud storage
  - CI/CD supply chain compromise detection

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

### v2.0 Quick Start

#### Testing Detection Rules

```bash
# Test a Sigma rule against scenario telemetry
curl -X POST http://localhost:8000/detection/test-rule \
  -H "Content-Type: application/json" \
  -d '{
    "rule_content": "$(cat detection_rules/sigma/iam_priv_escalation.yml)",
    "events": []  # Load from telemetry file
  }'

# List all available Sigma rules
curl http://localhost:8000/detection/rules

# Auto-generate a Sigma rule from a scenario
curl -X POST http://localhost:8000/detection/generate-rule \
  -H "Content-Type: application/json" \
  -d '{"scenario_name": "iam_priv_escalation"}'
```

#### Real-Time Streaming with WebSockets

```javascript
// Connect to live scenario generation stream
const ws = new WebSocket('ws://localhost:8000/ws/scenario/iam_priv_escalation');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'event_batch') {
    console.log(`Received ${data.events.length} events`);
  }
};

// Connect to live analysis stream
const analysisWs = new WebSocket('ws://localhost:8000/ws/analysis');
analysisWs.send(JSON.stringify({
  telemetry_path: './output/iam_escalation_demo/telemetry.jsonl'
}));
```

#### Enabling Redis Caching

```bash
# 1. Start Redis
docker run -d -p 6379:6379 redis:latest

# 2. Enable in .env
echo "REDIS_ENABLED=true" >> .env

# 3. Restart API server
docker-compose restart analysis-engine

# 4. Check cache stats
curl http://localhost:8000/cache/stats
```

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

### AI Integration (LLM & Threat Intelligence)

The simulator supports optional AI-powered analysis using Large Language Models and real-time threat intelligence. **It works perfectly without these features** using high-quality template-based analysis, but LLM integration provides more detailed, context-aware narratives.

#### LLM Integration (Optional)

Supports OpenAI GPT-4 and Anthropic Claude for AI-powered threat narratives, IOC analysis, and response planning.

**1. Configure via Environment Variables:**

```bash
# Edit .env file
LLM_PROVIDER=openai  # or 'anthropic' or 'none'
OPENAI_API_KEY=sk-...  # Your OpenAI API key
LLM_MODEL=gpt-4-turbo-preview  # Optional: specific model
```

**2. Use with CLI:**

```bash
# AI-powered analysis with OpenAI
python cli/analyze.py ./output/telemetry.jsonl \
  --llm-provider openai \
  --llm-api-key sk-... \
  --llm-model gpt-4-turbo-preview

# AI-powered analysis with Anthropic Claude
python cli/analyze.py ./output/telemetry.jsonl \
  --llm-provider anthropic \
  --llm-api-key sk-ant-... \
  --llm-model claude-3-5-sonnet-20241022

# Template-based (no API key needed)
python cli/analyze.py ./output/telemetry.jsonl
```

**3. API Server automatically picks up LLM config from environment**

```bash
# Set in .env, then start API
docker-compose up
```

#### Threat Intelligence Integration (Optional)

Enriches IOCs with real-time reputation data from AbuseIPDB and VirusTotal.

**1. Get API Keys:**
- AbuseIPDB: https://www.abuseipdb.com/api (free: 1000 requests/day)
- VirusTotal: https://www.virustotal.com/gui/join-us (free: 4 requests/min)

**2. Configure:**

```bash
# Edit .env file
ENABLE_THREAT_INTEL=true
ABUSEIPDB_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here
```

**3. Use with CLI:**

```bash
python cli/analyze.py ./output/telemetry.jsonl --enable-threat-intel
```

**What gets enriched:**
- IP addresses: Abuse reports, geolocation, reputation scores
- Domains: Malware associations, phishing status
- File hashes: Malware detection results (if present in logs)

**Example enriched output:**

```json
{
  "iocs": {
    "ip_addresses": ["203.0.113.42", "198.51.100.89"]
  },
  "threat_intelligence": {
    "ip": [
      {
        "ioc_value": "203.0.113.42",
        "threat_assessment": {
          "overall_threat_level": "high",
          "is_malicious": true,
          "confidence": 0.85
        },
        "enrichments": [
          {
            "provider": "AbuseIPDB",
            "abuse_confidence_score": 87,
            "total_reports": 143,
            "country_code": "CN"
          }
        ]
      }
    ]
  }
}
```

#### What Works Without API Keys

The simulator provides **full functionality** without any external API keys:

✅ All 6 attack scenarios generate realistic telemetry
✅ Event correlation and session detection
✅ MITRE ATT&CK technique mapping
✅ Kill chain stage classification
✅ IOC extraction (IPs, principals, resources)
✅ Template-based threat narratives (high quality)
✅ Template-based response plans
✅ SOC Dashboard visualization
✅ JSON and Markdown report generation

**LLM and threat intel are premium enhancements, not requirements.**

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
