# AI Threat Hunting Simulator

**A production-grade synthetic lab for AI-assisted threat hunting on cloud telemetry**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-6.0.0-green.svg)](https://github.com/yourusername/ai-threat-hunting-simulator/releases)
[![API](https://img.shields.io/badge/API-v6.0.0-blue.svg)](http://localhost:8000/docs)

> **v6.0.0 Release** - Complete Enterprise Platform: ML/Analytics, Multi-Cloud, Purple Team, Enterprise SSO, Compliance, SIEM Integration

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

### 🧠 v3.0 Features - Machine Learning & Advanced Analytics

- **ML-Based Anomaly Detection** - Production-ready isolation forest models
  - Unsupervised anomaly detection with sklearn Isolation Forest
  - 11-feature extraction from events (temporal, behavioral, metadata)
  - Statistical fallback when ML unavailable
  - Automatic threshold tuning and confidence scoring
  - Batch training on baseline data

- **Behavioral Baseline Learning** - Entity behavior profiling
  - Learn normal patterns per user/service/resource
  - Track typical hours, days, actions, resources, IPs
  - Deviation detection with confidence scores
  - Incremental learning support
  - Profile export/import for persistence

- **User Behavior Analytics (UBA)** - Advanced user monitoring
  - Per-user risk scoring based on anomalies
  - High-risk user identification
  - Behavioral anomaly aggregation
  - Combine ML and baseline detection

- **Event Classification** - Automatic categorization
  - 5 categories: authentication, authorization, data access, configuration, network
  - Confidence-based classification
  - Risk level assignment per category

- **Advanced Graph Analysis** - Attack path discovery
  - Build entity relationship graphs from events
  - Find attack paths between compromised entities
  - Calculate blast radius of breaches
  - Identify affected systems and resources
  - DFS/BFS algorithms for path finding

- **Automated Threat Hunting** - Pre-built hunt queries
  - Query engine supporting Sigma/KQL/SPL formats
  - 7+ default hunt queries for common techniques
  - MITRE ATT&CK technique mapping
  - Customizable query library
  - Scheduled hunting campaigns

### ☁️ v4.0 Features - Multi-Cloud Support

- **SIEM Integrations** - Export to major SIEM platforms
  - **Splunk** - HEC format with SPL query generation
  - **Elastic/ELK** - ECS format with KQL queries
  - **Google Chronicle** - UDM format with YARA-L rules
  - **Azure Sentinel** - Custom log format with KQL
  - **IBM QRadar** - LEEF format with AQL queries
  - Batch event export with configurable buffers
  - Connection health monitoring

- **Detection Rule Conversion** - Universal rule format
  - Convert rules between SIEM query languages
  - Support for SPL, KQL, YARA-L, AQL
  - 7 pre-built detection rules for common attacks
  - MITRE technique tagging

- **Azure Attack Scenarios** - Microsoft cloud attacks
  - IAM privilege escalation with AD role assignment
  - Blob Storage data exfiltration (847 files, 125GB)
  - VM persistence with custom script extensions
  - Managed identity privilege escalation
  - Azure Key Vault secret access
  - Lateral movement via Azure Bastion
  - C2 via Azure Functions

- **GCP Attack Scenarios** - Google Cloud attacks
  - IAM policy modification for privilege escalation
  - Cloud Storage exfiltration (2100 objects, 340GB)
  - GKE container escape with metadata exploitation
  - Kubernetes cluster takeover
  - DaemonSet cryptominer deployment
  - Service account key theft
  - Cross-project lateral movement

- **Multi-Cloud Event Schema** - Unified telemetry format
  - Cloud-agnostic event structure
  - Support for AWS, Azure, GCP events
  - Automatic provider detection

### 🎮 v5.0 Features - Purple Team Collaboration

- **CTF Mode** - Security training challenges
  - 5 difficulty levels: beginner to expert
  - 6 challenge categories: anomaly detection, threat hunting, IR, forensics, MITRE mapping, log analysis
  - Flag submission and validation system
  - Real-time leaderboard with ranking
  - Hint system with point penalties
  - Progress tracking per user
  - Pre-built challenges with realistic scenarios

- **Exercise Management** - Team training orchestration
  - Complete exercise lifecycle (scheduled → in-progress → completed)
  - 4 exercise templates:
    - Ransomware incident response
    - APT detection and hunting
    - Cloud breach response
    - Insider threat investigation
  - Multi-objective tracking with MITRE ATT&CK mapping
  - Role assignment: red/blue/purple team, observers
  - Event recording during exercises
  - Comprehensive metrics and reports
  - Exercise scheduling calendar

- **Real-Time Collaboration** - Live team coordination
  - WebSocket-based live messaging
  - Chat with threaded conversations
  - System alerts and notifications
  - Event annotations and tagging
  - Detection broadcasting to team
  - User presence tracking (online/away/busy/offline)
  - Typing indicators
  - @mentions support
  - Message search and filtering
  - Priority levels (low/normal/high/urgent)
  - Read receipts

- **Purple Team Exercises** - Red/Blue collaboration
  - Exercise scoring based on detection rates
  - Red team action recording
  - Blue team detection tracking
  - Automated grading (A/B/C based on detection rate >90%/70%/50%)
  - Performance metrics and improvement tracking

### 🏢 v6.0 Features - Enterprise Production Deployments

- **Audit Logging** - Tamper-evident compliance logs
  - Comprehensive event tracking (14 event types)
  - SHA-256 hash chain for tamper detection
  - Integrity verification with cryptographic proof
  - Activity summaries per actor/tenant
  - Anomaly detection:
    - Excessive failed authentication (≥5 failures)
    - Unusual time access (outside business hours)
    - Bulk data export detection
    - Privilege escalation attempts
  - Query API with filters (event type, actor, resource, time range)
  - Compliance export for auditors

- **Compliance Reporting** - Multi-standard support
  - **SOC 2** Trust Services Criteria
  - **ISO 27001** Information Security
  - **NIST Cybersecurity Framework**
  - **HIPAA** Healthcare Privacy
  - **PCI DSS** Payment Card Industry
  - **GDPR** EU Data Protection
  - **CCPA** California Privacy
  - **FedRAMP** Federal Cloud Security
  - 25+ pre-configured compliance controls
  - Automated assessment with scoring
  - Control status tracking (implemented/partial/not implemented)
  - Evidence collection and documentation
  - Findings and recommendations generation
  - Compliance dashboard across all standards

- **Advanced RBAC** - Fine-grained access control
  - 28 granular permissions across all features
  - 9 pre-defined roles:
    - Super Administrator (full access)
    - Tenant Administrator (tenant-scoped full access)
    - Security Analyst (threat analysis)
    - SOC Operator (event monitoring)
    - Red/Blue/Purple Team (exercise participation)
    - Compliance Auditor (audit/compliance access)
    - Read-Only User (view-only)
  - Custom role creation with permission sets
  - Tenant-scoped role assignments
  - Time-limited assignments with expiration
  - Permission checking API
  - Comprehensive access audits

- **Enterprise SSO/SAML** - Identity federation
  - SAML 2.0 authentication
  - OpenID Connect (OIDC) support
  - Integration with:
    - Okta
    - Azure AD
    - Google Workspace
    - OneLogin
    - Auth0
  - Automatic user provisioning
  - Session management

- **Multi-Tenancy** - Isolated customer deployments
  - Complete tenant isolation
  - Per-tenant quotas (events/day, users)
  - Feature flags per tenant
  - Tenant-scoped data access
  - Cross-tenant admin capabilities for MSPs

- **License Management** - Commercial deployment support
  - 3-tier licensing:
    - **Starter**: Basic detection, event analysis
    - **Professional**: ML detection, threat hunting, CTF mode
    - **Enterprise**: All features, SSO, compliance, multi-tenancy
  - User and event quota enforcement
  - Feature flag enforcement per tier
  - License key validation
  - Usage tracking and reporting
  - Expiration warnings (30-day notice)

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

## API Reference

### v2.0 API Endpoints

The Analysis Engine API (v3.0.0) provides comprehensive RESTful and WebSocket endpoints:

#### Core Analysis Endpoints

```bash
# Upload and analyze telemetry file
POST /analyze/upload
Content-Type: multipart/form-data
Authorization: Bearer <API_KEY>

# Analyze JSON events directly
POST /analyze/data
Content-Type: application/json
Body: { "events": [...] }

# Health check with component status
GET /health

# Prometheus metrics
GET /metrics

# Statistics (JSON format)
GET /stats
```

#### Detection Rule Testing Endpoints (v2.0)

```bash
# Test a single Sigma rule
POST /detection/test-rule
Content-Type: application/json
Body: {
  "rule_content": "title: My Rule\n...",
  "events": [...],
  "ground_truth": ["event_id_1", "event_id_2"]  # Optional
}
Response: {
  "status": "success",
  "total_events": 100,
  "matched_events": 15,
  "true_positives": 12,
  "false_positives": 3,
  "precision": 0.8000,
  "recall": 0.9231,
  "f1_score": 0.8571,
  "accuracy": 0.9700
}

# Batch test multiple rules
POST /detection/test-rules-batch
Body: {
  "rules": [
    {"name": "rule1", "content": "..."},
    {"name": "rule2", "content": "..."}
  ],
  "events": [...]
}

# List all available Sigma rules
GET /detection/rules
Response: {
  "total_rules": 6,
  "rules": [
    {
      "name": "iam_priv_escalation",
      "title": "AWS IAM PassRole Privilege Escalation",
      "level": "high",
      "tags": ["attack.privilege_escalation", "attack.t1548.005"]
    }
  ]
}

# Get specific rule
GET /detection/rules/{rule_name}

# Auto-generate Sigma rule from scenario
POST /detection/generate-rule
Body: {
  "scenario_name": "iam_priv_escalation",
  "events": []  # Optional, loads from scenario if empty
}
Response: {
  "status": "success",
  "rule_content": "title: Auto-Generated...\n..."
}
```

#### WebSocket Endpoints (v2.0)

```javascript
// Real-time scenario generation streaming
const ws = new WebSocket('ws://localhost:8000/ws/scenario/iam_priv_escalation');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  switch(data.type) {
    case 'scenario_start':
      console.log('Scenario started:', data.scenario_name);
      break;
    case 'event_batch':
      console.log(`Received ${data.events.length} events`);
      console.log('Total so far:', data.total_count);
      break;
    case 'scenario_complete':
      console.log('Generation complete:', data.total_events);
      break;
  }
};

// Real-time analysis streaming
const analysisWs = new WebSocket('ws://localhost:8000/ws/analysis');
analysisWs.onopen = () => {
  analysisWs.send(JSON.stringify({
    telemetry_path: './output/scenarios/demo/telemetry.jsonl'
  }));
};
analysisWs.onmessage = (event) => {
  const data = JSON.parse(event.data);
  switch(data.type) {
    case 'analysis_start':
      console.log('Analysis started');
      break;
    case 'analysis_progress':
      console.log(`Progress: ${data.progress_percent}%`);
      break;
    case 'session_detected':
      console.log('Suspicious session:', data.session);
      break;
    case 'analysis_complete':
      console.log('Results:', data.results);
      break;
  }
};

// Live telemetry feed (broadcast)
const liveWs = new WebSocket('ws://localhost:8000/ws/live');
liveWs.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'heartbeat') {
    console.log('Active connections:', data.active_connections);
  }
};
// Send commands
liveWs.send('stats');  // Get WebSocket statistics
liveWs.send('ping');   // Heartbeat ping
```

#### Cache Endpoints (v2.0)

```bash
# Get cache statistics
GET /cache/stats
Response: {
  "enabled": true,
  "connected": true,
  "stats": {
    "hits": 1523,
    "misses": 89,
    "sets": 245,
    "deletes": 12,
    "errors": 0,
    "total_operations": 1612,
    "hit_rate_percent": 94.48
  }
}

# WebSocket statistics
GET /ws/stats
Response: {
  "total_connections": 5,
  "total_topics": 3,
  "topics": {
    "live_feed": 2,
    "scenario_iam_priv_escalation": 1,
    "analysis": 2
  }
}
```

#### Scenario Management Endpoints

```bash
# List all scenarios
GET /scenarios

# Get specific scenario
GET /scenarios/{scenario_name}

# Delete scenario (admin only)
DELETE /scenarios/{scenario_name}
Authorization: Bearer <ADMIN_API_KEY>
```

#### Database Endpoints (Optional)

```bash
# List analysis runs
GET /database/analyses?limit=50&offset=0

# Get specific analysis run
GET /database/analyses/{run_id}

# Get session IOCs
GET /database/sessions/{session_id}/iocs
```

### Response Codes

- `200` - Success
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (missing/invalid API key)
- `404` - Not Found
- `429` - Too Many Requests (rate limit exceeded)
- `500` - Internal Server Error

### Rate Limits

- `/analyze/upload`: 10 requests/minute
- `/analyze/data`: 20 requests/minute
- `/detection/test-rule`: 10 requests/minute
- `/detection/test-rules-batch`: 5 requests/minute
- `/detection/generate-rule`: 5 requests/minute
- Most GET endpoints: 30 requests/minute

## Deployment Guide

### Docker Deployment (Recommended)

**Full stack with Redis caching:**

```yaml
# docker-compose.yml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  analysis-engine:
    build: .
    ports:
      - "8000:8000"
    environment:
      - REDIS_ENABLED=true
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - DB_CONNECTION_STRING=postgresql://user:pass@postgres:5432/threatdb
    depends_on:
      - redis
      - postgres
    volumes:
      - ./output:/app/output
      - ./detection_rules:/app/detection_rules

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=threatuser
      - POSTGRES_PASSWORD=changeme
      - POSTGRES_DB=threatdb
    volumes:
      - postgres_data:/var/lib/postgresql/data

  soc-dashboard:
    build: ./ui/soc_dashboard
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:8000
    depends_on:
      - analysis-engine

volumes:
  redis_data:
  postgres_data:
```

**Start services:**

```bash
docker-compose up -d
docker-compose logs -f  # View logs
docker-compose ps       # Check status
```

### Kubernetes Deployment

**Redis Cache:**

```yaml
# redis-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: redis-storage
          mountPath: /data
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: redis-storage
        persistentVolumeClaim:
          claimName: redis-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: redis
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
```

**Analysis Engine:**

```yaml
# analysis-engine-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: analysis-engine
spec:
  replicas: 3
  selector:
    matchLabels:
      app: analysis-engine
  template:
    metadata:
      labels:
        app: analysis-engine
    spec:
      containers:
      - name: analysis-engine
        image: your-registry/analysis-engine:v2.0.0
        ports:
        - containerPort: 8000
        env:
        - name: REDIS_ENABLED
          value: "true"
        - name: REDIS_HOST
          value: "redis"
        - name: REDIS_PORT
          value: "6379"
        - name: API_WORKERS
          value: "4"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: analysis-engine
spec:
  type: LoadBalancer
  selector:
    app: analysis-engine
  ports:
  - port: 80
    targetPort: 8000
```

**Deploy:**

```bash
kubectl apply -f redis-deployment.yaml
kubectl apply -f analysis-engine-deployment.yaml
kubectl get pods  # Check status
kubectl logs -f deployment/analysis-engine  # View logs
```

### Production Configuration

**.env for production:**

```bash
# API Configuration
ANALYSIS_API_HOST=0.0.0.0
ANALYSIS_API_PORT=8000
API_WORKERS=4
API_KEY=<generate-strong-random-key>
ADMIN_API_KEY=<generate-strong-admin-key>
ALLOWED_ORIGINS=https://soc.yourcompany.com,https://dashboard.yourcompany.com

# Redis Caching (Production)
REDIS_ENABLED=true
REDIS_HOST=redis-cluster.internal
REDIS_PORT=6379
REDIS_PASSWORD=<strong-redis-password>
REDIS_CACHE_TTL=3600
REDIS_MAX_CONNECTIONS=100

# Database (PostgreSQL recommended for production)
DB_CONNECTION_STRING=postgresql://user:pass@postgres-cluster:5432/threatdb?sslmode=require
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40

# Security
ENABLE_HSTS=true
MAX_UPLOAD_SIZE_MB=500
MAX_EVENTS_PER_REQUEST=50000

# Performance
MAX_CONCURRENT_ANALYSES=10
STREAMING_CHUNK_SIZE=5000

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
SENTRY_DSN=https://...@sentry.io/...

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=/var/log/threat-hunting/api.log
```

## Troubleshooting

### Common Issues

**1. Redis Connection Failed**

```bash
# Check Redis is running
docker ps | grep redis
# Or
redis-cli ping

# Test connection
redis-cli -h localhost -p 6379 ping
# Expected: PONG

# Check logs
docker logs redis
```

**Solution:** Ensure Redis is running and accessible. Set `REDIS_ENABLED=false` to disable caching if not needed.

**2. WebSocket Connection Refused**

```bash
# Check firewall
sudo ufw status
sudo ufw allow 8000/tcp

# Test WebSocket endpoint
wscat -c ws://localhost:8000/ws/live
```

**Solution:** Ensure WebSocket upgrade headers are allowed through reverse proxies (nginx, CloudFlare).

**3. Sigma Rule Parsing Errors**

```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('detection_rules/sigma/iam_priv_escalation.yml'))"

# Test rule
curl -X POST http://localhost:8000/detection/test-rule \
  -H "Content-Type: application/json" \
  -d @test_payload.json
```

**Solution:** Ensure Sigma rules follow proper YAML syntax. Check `detection` and `logsource` fields.

**4. High Memory Usage**

```bash
# Check cache size
curl http://localhost:8000/cache/stats

# Clear cache
redis-cli FLUSHDB

# Reduce cache TTL
export REDIS_CACHE_TTL=1800  # 30 minutes
```

**Solution:** Adjust `REDIS_CACHE_TTL` or `MAX_CONCURRENT_ANALYSES` in .env file.

**5. Rate Limit Exceeded**

```
HTTP 429 Too Many Requests
```

**Solution:** Implement request batching or contact admin to increase limits in `slowapi` configuration.

### Performance Tuning

**For high-throughput scenarios:**

```bash
# Increase API workers
API_WORKERS=8

# Increase Redis connection pool
REDIS_MAX_CONNECTIONS=200

# Increase database pool
DB_POOL_SIZE=50
DB_MAX_OVERFLOW=100

# Batch processing
MAX_CONCURRENT_ANALYSES=20
STREAMING_CHUNK_SIZE=10000
```

**For low-latency real-time streaming:**

```bash
# Reduce batch size
STREAMING_CHUNK_SIZE=100

# Reduce cache TTL for fresher data
REDIS_CACHE_TTL=300  # 5 minutes

# Increase workers
API_WORKERS=4
```

## Testing Detection Rules

### Example: Testing IAM Privilege Escalation Rule

```python
import requests
import json

# Load Sigma rule
with open('detection_rules/sigma/iam_priv_escalation.yml') as f:
    rule_content = f.read()

# Load telemetry events
with open('output/scenarios/iam_priv_escalation/telemetry.jsonl') as f:
    events = [json.loads(line) for line in f if line.strip()]

# Test rule
response = requests.post(
    'http://localhost:8000/detection/test-rule',
    json={
        'rule_content': rule_content,
        'events': events
    },
    headers={'Authorization': 'Bearer your-api-key'}
)

result = response.json()
print(f"Precision: {result['precision']:.2%}")
print(f"Recall: {result['recall']:.2%}")
print(f"F1 Score: {result['f1_score']:.2%}")
print(f"Matched: {result['matched_events']}/{result['total_events']} events")
```

### Batch Testing All Rules

```python
import os
import glob

rules_dir = 'detection_rules/sigma'
rules = []

for rule_file in glob.glob(f'{rules_dir}/*.yml'):
    with open(rule_file) as f:
        rules.append({
            'name': os.path.basename(rule_file),
            'content': f.read()
        })

response = requests.post(
    'http://localhost:8000/detection/test-rules-batch',
    json={
        'rules': rules,
        'events': events
    }
)

results = response.json()
for rule_result in results['results']:
    print(f"{rule_result['name']}: F1={rule_result['f1_score']:.3f}")
```

## Advanced Usage

### Custom Sigma Rule Development

```yaml
# detection_rules/sigma/custom_attack.yml
title: Custom Attack Pattern Detection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects custom attack pattern in cloud logs
author: Your Security Team
date: 2025/11/17
tags:
    - attack.execution
    - attack.t1059
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_suspicious:
        event_type|contains:
            - 'lambda.invoke'
            - 'ec2.run_instances'
        principal|contains: 'suspicious'
    selection_high_volume:
        # Detected when multiple events match
        event_type: '*'
    condition: selection_suspicious
falsepositives:
    - Legitimate automation
level: high
```

### Programmatic Analysis with Python SDK

```python
from analysis_engine.pipeline import ThreatHuntingPipeline
from analysis_engine.cache import init_cache, CacheConfig

# Initialize with caching
cache_config = CacheConfig(
    enabled=True,
    redis_host='localhost',
    default_ttl=7200  # 2 hours
)
cache = init_cache(cache_config)

# Initialize pipeline
pipeline = ThreatHuntingPipeline(
    time_window_minutes=60,
    min_events_for_session=3,
    risk_threshold=0.6,
    enable_database=True,
    llm_provider_type='openai',
    llm_api_key='sk-...'
)

# Analyze telemetry
results = pipeline.analyze_telemetry_file(
    './output/scenarios/demo/telemetry.jsonl'
)

# Access results
print(f"Detected {results['total_sessions']} sessions")
print(f"Suspicious: {results['suspicious_sessions']}")

for session in results['sessions']:
    if session['is_malicious']:
        print(f"Malicious session: {session['session_id']}")
        print(f"Risk score: {session['risk_score']}")
        print(f"MITRE techniques: {session['mitre_techniques']}")
```

### WebSocket Client Example (Python)

```python
import asyncio
import websockets
import json

async def stream_scenario():
    uri = "ws://localhost:8000/ws/scenario/iam_priv_escalation"

    async with websockets.connect(uri) as websocket:
        async for message in websocket:
            data = json.loads(message)

            if data['type'] == 'event_batch':
                events = data['events']
                print(f"Received batch of {len(events)} events")

                # Process events
                for event in events:
                    print(f"  - {event['event_type']}: {event.get('action', 'N/A')}")

            elif data['type'] == 'scenario_complete':
                print(f"Generation complete: {data['total_events']} total events")
                break

asyncio.run(stream_scenario())
```

## Project Structure

```
ai-threat-hunting-simulator/
├── README.md
├── ROADMAP.md                      # v2.0-v6.0 feature roadmap
├── CODE_OF_CONDUCT.md              # Community guidelines
├── LICENSE
├── docker-compose.yml
├── .env.example
├── requirements.txt
├── quickstart.sh                   # Interactive setup script
│
├── generator/                      # Synthetic telemetry generation
│   ├── attack_traces/              # 6 attack scenario definitions
│   │   ├── iam_priv_escalation/
│   │   ├── container_escape/
│   │   ├── cred_stuffing/
│   │   ├── lateral_movement/
│   │   ├── data_exfiltration/
│   │   └── supply_chain/
│   ├── cloud_topologies/           # Simulated cloud environments
│   ├── schemas/                    # Data schemas & validators
│   └── telemetry_synthesizer.py   # Core telemetry generation
│
├── analysis_engine/                # AI-powered analysis pipeline
│   ├── core/                       # Core analysis components
│   │   ├── loader.py               # Telemetry loading
│   │   ├── parser.py               # Event parsing
│   │   ├── correlator.py           # Event correlation
│   │   ├── graph_correlator.py     # Graph-based correlation
│   │   ├── kill_chain.py           # Kill chain mapping
│   │   └── mitre.py                # MITRE ATT&CK mapping
│   ├── agents/                     # AI agents
│   │   ├── ioc_extractor.py        # IOC extraction agent
│   │   ├── narrative.py            # Threat narrative agent
│   │   └── response_planner.py     # Response planning agent
│   ├── detection/                  # v2.0: Detection rule testing
│   │   ├── __init__.py
│   │   └── rule_tester.py          # Sigma rule testing framework
│   ├── api/                        # FastAPI REST + WebSocket API
│   │   ├── server.py               # Main API server (v3.0.0)
│   │   ├── auth.py                 # Authentication
│   │   ├── models.py               # Pydantic request/response models
│   │   ├── security.py             # Security middleware
│   │   └── websocket.py            # v2.0: WebSocket streaming
│   ├── database/                   # PostgreSQL persistence layer
│   │   ├── __init__.py
│   │   ├── models.py               # SQLAlchemy models
│   │   └── repositories.py         # Data access layer
│   ├── llm/                        # LLM integration (OpenAI, Anthropic)
│   ├── threat_intel/               # Threat intelligence enrichment
│   ├── monitoring/                 # Prometheus metrics
│   ├── cache.py                    # v2.0: Redis caching layer
│   ├── pipeline.py                 # Main analysis orchestrator
│   └── reports/                    # Report generators (JSON, Markdown)
│
├── detection_rules/                # v2.0: Sigma detection rules
│   └── sigma/                      # Sigma rule library
│       ├── iam_priv_escalation.yml
│       ├── container_escape.yml
│       ├── cred_stuffing.yml
│       ├── lateral_movement.yml
│       ├── data_exfiltration.yml
│       └── supply_chain.yml
│
├── ui/                             # SOC Dashboard (React TypeScript)
│   └── soc_dashboard/
│       ├── src/
│       │   ├── components/         # React components
│       │   │   ├── ScenarioSelection.tsx
│       │   │   ├── TimelineView.tsx
│       │   │   ├── AttackGraphView.tsx
│       │   │   └── AnalysisView.tsx
│       │   ├── api/                # API client
│       │   │   └── client.ts
│       │   └── App.tsx
│       ├── package.json
│       └── Dockerfile
│
├── cli/                            # Command-line tools
│   ├── run_scenario.py             # End-to-end scenario runner
│   ├── analyze.py                  # Telemetry analyzer
│   └── validate_traces.py          # Trace validator
│
├── tests/                          # Test suites
│   ├── test_scenarios.py           # Scenario generation tests
│   ├── test_detection.py           # Detection rule tests
│   ├── test_api.py                 # API integration tests
│   └── test_cache.py               # Cache layer tests
│
├── docs/                           # Documentation
│   ├── DEPLOYMENT.md               # Deployment guide
│   ├── API.md                      # API reference
│   └── DEVELOPMENT.md              # Developer guide
│
├── notebooks/                      # Jupyter notebooks
│   ├── scenario_analysis.ipynb     # Interactive scenario analysis
│   └── detection_tuning.ipynb      # Detection rule tuning
│
├── scripts/                        # Utility scripts
│   ├── setup_db.py                 # Database setup
│   └── generate_test_data.py       # Test data generator
│
├── .github/                        # GitHub workflows
│   └── workflows/
│       └── ci.yml                  # CI/CD pipeline (7 jobs)
│
└── output/                         # Generated output (gitignored)
    ├── scenarios/                  # Scenario outputs
    ├── telemetry/                  # Raw telemetry
    └── reports/                    # Analysis reports
```

### Key Directories (v2.0)

- **`detection_rules/sigma/`** - Production-ready Sigma detection rules for all 6 scenarios
- **`analysis_engine/detection/`** - Detection rule testing framework with TP/FP/FN metrics
- **`analysis_engine/cache.py`** - Redis caching layer for performance optimization
- **`analysis_engine/api/websocket.py`** - Real-time WebSocket streaming infrastructure
- **`ROADMAP.md`** - Strategic roadmap with market research and v2.0-v6.0 features

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

## Version History

### v2.0.0 (2025-11-17) - Detection & Validation

**Major Features:**
- 🎯 **Detection Rule Testing Framework** - Comprehensive Sigma rule testing with precision/recall metrics
- 🌐 **Real-Time Streaming** - WebSocket support for live scenario generation and analysis
- ⚡ **Redis Caching Layer** - Performance optimization with intelligent caching (94%+ hit rates)
- 📊 **15+ New API Endpoints** - Detection testing, rule management, caching, WebSocket stats
- 📚 **Complete Sigma Rule Library** - 6 production-ready rules covering all attack scenarios
- 🚀 **Market Research & Roadmap** - Competitive analysis and strategic planning (v2.0-v6.0)

**Technical Improvements:**
- API upgraded to v3.0.0 with enhanced capabilities
- Batch rule testing (up to 50 rules simultaneously)
- Auto-generation of Sigma rules from telemetry
- Multi-namespace caching with configurable TTL
- Topic-based pub/sub WebSocket messaging
- Connection health monitoring with heartbeats
- TP/FP/FN/TN metrics for rule validation
- Coverage reports and recommendations

**New Files:**
- `ROADMAP.md` - Strategic product roadmap
- `analysis_engine/detection/rule_tester.py` - Detection framework (312 lines)
- `analysis_engine/api/websocket.py` - WebSocket infrastructure (500+ lines)
- `analysis_engine/cache.py` - Redis caching layer (530+ lines)
- `detection_rules/sigma/*.yml` - 6 Sigma rules

**Documentation:**
- Comprehensive API reference with examples
- Deployment guide (Docker, Kubernetes, Production)
- Troubleshooting and performance tuning guides
- Advanced usage examples (Python SDK, WebSockets)
- Testing detection rules documentation

**Commits:** 4 major commits, 2,780+ lines added

---

### v1.0.0 - Foundation

**Initial Release Features:**
- 🎯 6 realistic cloud attack scenarios (IAM, Container, Lateral Movement, etc.)
- 🔬 Synthetic telemetry generation (CloudTrail, VPC Flow, Container logs)
- 🤖 AI-powered analysis engine with LLM support
- 📊 SOC Dashboard UI (React TypeScript)
- 🔗 MITRE ATT&CK technique mapping
- 📈 Kill chain stage classification
- 🔍 IOC extraction and enrichment
- 💾 PostgreSQL database persistence
- 📝 JSON and Markdown report generation
- 🐳 Docker Compose deployment
- 🔐 Security features (auth, rate limiting, file validation)
- 📊 Prometheus metrics integration
- 🧪 GitHub Actions CI/CD pipeline

**Architecture:**
- Modular pipeline design
- Template-based fallback (no API keys required)
- Optional LLM integration (OpenAI GPT-4, Anthropic Claude)
- Optional threat intelligence (AbuseIPDB, VirusTotal)
- Graph-based correlation engine
- Multi-agent analysis system

## Support

- **Documentation**: [docs/](docs/)
- **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs) (when running)
- **Issues**: [GitHub Issues](https://github.com/yourusername/ai-threat-hunting-simulator/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/ai-threat-hunting-simulator/discussions)
- **Roadmap**: [ROADMAP.md](ROADMAP.md)

### Quick Links

- 📖 [API Reference](#api-reference) - Complete endpoint documentation
- 🚀 [Deployment Guide](#deployment-guide) - Docker, Kubernetes, Production
- 🔧 [Troubleshooting](#troubleshooting) - Common issues and solutions
- 🧪 [Testing Detection Rules](#testing-detection-rules) - Sigma rule validation
- 🎓 [Advanced Usage](#advanced-usage) - Python SDK and WebSocket examples

---

**Built for the security community, by security practitioners.**

**Version**: 2.0.0 | **API Version**: 3.0.0 | **Released**: November 17, 2025
