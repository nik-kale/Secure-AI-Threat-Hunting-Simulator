# AI Threat Hunting Simulator - Version 3 Roadmap

## Executive Summary

This document outlines critical fixes, gaps, and strategic enhancements to evolve the AI Threat Hunting Simulator from v1.0 to v3.0.

---

## CRITICAL ISSUES TO FIX (v1.1 Patch)

### 1. Python Compatibility Issue
**Location**: `analysis_engine/core/kill_chain.py:98`
**Problem**: Using `KillChainStage | None` syntax (Python 3.10+) without version constraint
**Fix**:
```python
# Change from:
def map_event(self, event: NormalizedEvent) -> KillChainStage | None:

# To:
from typing import Optional
def map_event(self, event: NormalizedEvent) -> Optional[KillChainStage]:
```

### 2. Missing Package Files
**Location**: All attack trace subdirectories
**Problem**: Missing `__init__.py` causes import failures
**Fix**: Add to each subdirectory:
```python
# generator/attack_traces/iam_priv_escalation/__init__.py
"""IAM Privilege Escalation attack scenario."""
from .generator import generate_iam_privilege_escalation_scenario

__all__ = ["generate_iam_privilege_escalation_scenario"]
```

### 3. Security - CORS Configuration
**Location**: `analysis_engine/api/server.py:24-30`
**Problem**: Allows all origins with credentials
**Fix**:
```python
import os

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
```

### 4. Timestamp Distribution Bug
**Location**: `generator/telemetry_synthesizer.py:317-322`
**Problem**: Noise events reuse attack timestamps
**Fix**:
```python
def add_benign_noise(self, events: List[Dict[str, Any]], noise_ratio: float = 0.3):
    # Extract time range
    if not events:
        return events

    timestamps = [self._parse_timestamp(e["timestamp"]) for e in events]
    start_time = min(timestamps)
    end_time = max(timestamps)
    duration_seconds = (end_time - start_time).total_seconds()

    num_noise_events = int(len(events) * noise_ratio)
    noise_events = []

    for _ in range(num_noise_events):
        # Generate random time within range
        random_offset = random.uniform(0, duration_seconds)
        timestamp = generate_timestamp(start_time, random_offset)

        # ... rest of noise generation
```

### 5. File Descriptor Leak
**Location**: `analysis_engine/api/server.py:65-78`
**Problem**: Temp files not cleaned on exception
**Fix**:
```python
@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)) -> Dict[str, Any]:
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='wb',
            suffix=Path(file.filename).suffix,
            delete=False
        ) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = Path(tmp_file.name)

        results = pipeline.analyze_telemetry_file(tmp_path)
        return results

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()
```

---

## VERSION 2.0 ENHANCEMENTS

### Architecture Improvements

#### 1. Proper Package Structure
**Create** `setup.py`:
```python
from setuptools import setup, find_packages

setup(
    name="ai-threat-hunting-simulator",
    version="2.0.0",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "pydantic>=2.5.0",
        "fastapi>=0.104.0",
        # ... rest from requirements.txt
    ],
    extras_require={
        "dev": ["pytest>=7.4.0", "black>=23.11.0", "mypy>=1.7.0"],
        "llm": ["openai>=1.3.0", "anthropic>=0.7.0"],
    },
    entry_points={
        "console_scripts": [
            "threat-hunt=cli.run_scenario:run_scenario",
            "threat-validate=cli.validate_traces:validate_traces",
        ],
    },
)
```

**Install as package**:
```bash
pip install -e .
```

**Benefits**:
- Proper imports without sys.path hacks
- Installable CLI commands
- Dependency management

#### 2. Configuration Management
**Create** `config.py`:
```python
from pydantic import BaseSettings, Field
from typing import List

class Settings(BaseSettings):
    # API Configuration
    api_host: str = Field("0.0.0.0", env="ANALYSIS_API_HOST")
    api_port: int = Field(8000, env="ANALYSIS_API_PORT")
    api_debug: bool = Field(False, env="ANALYSIS_API_DEBUG")

    # CORS
    allowed_origins: List[str] = Field(
        ["http://localhost:3000"],
        env="ALLOWED_ORIGINS"
    )

    # Analysis
    correlation_time_window: int = Field(60, env="CORRELATION_TIME_WINDOW_MINUTES")
    min_events_for_alert: int = Field(3, env="MIN_EVENTS_FOR_ALERT")
    risk_score_threshold: float = Field(0.5, env="RISK_SCORE_THRESHOLD")

    # Generation
    default_account_id: str = Field("123456789012", env="DEFAULT_ACCOUNT_ID")
    default_region: str = Field("us-east-1", env="DEFAULT_REGION")

    # Security
    api_key_header: str = "X-API-Key"
    max_upload_size_mb: int = 100

    # LLM Integration (optional)
    openai_api_key: str = Field(None, env="OPENAI_API_KEY")
    anthropic_api_key: str = Field(None, env="ANTHROPIC_API_KEY")
    llm_provider: str = Field("none", env="LLM_PROVIDER")

    class Config:
        env_file = ".env"

settings = Settings()
```

#### 3. API Security Layer
**Create** `analysis_engine/api/security.py`:
```python
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

# API Key Authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Verify API key from environment."""
    expected_key = os.getenv("API_KEY")

    if not expected_key:
        # No API key configured - allow access (development mode)
        return None

    if api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key"
        )
    return api_key

# Rate Limiting
limiter = Limiter(key_func=get_remote_address)
```

**Update** `analysis_engine/api/server.py`:
```python
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from .security import limiter, verify_api_key

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/analyze/upload", dependencies=[Security(verify_api_key)])
@limiter.limit("10/minute")
async def analyze_upload(request: Request, file: UploadFile = File(...)):
    # ... existing code
```

#### 4. Database Persistence Layer
**Create** `analysis_engine/database/models.py`:
```python
from sqlalchemy import Column, String, JSON, DateTime, Float, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id = Column(String, primary_key=True)
    scenario_name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    num_events = Column(Integer)
    num_sessions = Column(Integer)
    num_suspicious = Column(Integer)
    results = Column(JSON)

class DetectedSession(Base):
    __tablename__ = "detected_sessions"

    id = Column(String, primary_key=True)
    analysis_run_id = Column(String, ForeignKey("analysis_runs.id"))
    session_id = Column(String, nullable=False)
    risk_score = Column(Float)
    is_malicious = Column(Boolean)
    kill_chain_stages = Column(JSON)
    mitre_techniques = Column(JSON)
    iocs = Column(JSON)
    narrative = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String, primary_key=True)
    session_id = Column(String, ForeignKey("detected_sessions.id"))
    ioc_type = Column(String)  # ip_address, principal, command, etc.
    value = Column(String)
    severity = Column(String)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
```

**Benefits**:
- Historical analysis tracking
- IOC correlation across scenarios
- Performance metrics
- Audit trail

#### 5. Streaming Analysis for Large Files
**Create** `analysis_engine/core/streaming_loader.py`:
```python
from typing import Iterator, Dict, Any
import json

class StreamingTelemetryLoader:
    """Load and process telemetry in chunks."""

    def __init__(self, chunk_size: int = 1000):
        self.chunk_size = chunk_size

    def load_chunks(self, file_path: Path) -> Iterator[List[Dict[str, Any]]]:
        """Yield chunks of events."""
        chunk = []

        with open(file_path, 'r') as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)
                    chunk.append(event)

                    if len(chunk) >= self.chunk_size:
                        yield chunk
                        chunk = []

        # Yield remaining events
        if chunk:
            yield chunk

class StreamingPipeline(ThreatHuntingPipeline):
    """Pipeline with streaming support for large files."""

    def analyze_telemetry_stream(
        self,
        telemetry_path: Path,
        chunk_size: int = 1000
    ) -> Dict[str, Any]:
        """Analyze telemetry in chunks."""
        loader = StreamingTelemetryLoader(chunk_size)

        all_sessions = []
        total_events = 0

        for chunk in loader.load_chunks(telemetry_path):
            normalized = self.parser.parse_events(chunk)
            sessions = self.correlator.correlate_multi_criteria(normalized)
            all_sessions.extend(sessions)
            total_events += len(chunk)

        # Merge overlapping sessions across chunks
        merged_sessions = self._merge_sessions(all_sessions)

        # Continue with normal analysis
        suspicious = self.correlator.identify_suspicious_sessions(merged_sessions)
        # ...
```

---

## VERSION 3.0 STRATEGIC ENHANCEMENTS

### Feature Set Expansion

#### 1. Advanced Attack Scenarios

**Lateral Movement Scenario**:
```python
# generator/attack_traces/lateral_movement/generator.py
def generate_lateral_movement_scenario(output_dir: Path):
    """
    Multi-account lateral movement via AssumeRole.

    Attack Chain:
    1. Initial access to Dev account
    2. Discover cross-account roles
    3. AssumeRole to Production account
    4. Enumerate sensitive resources
    5. Data exfiltration
    """
    # Implementation with cross-account events
```

**Data Exfiltration Scenario**:
```python
# generator/attack_traces/data_exfiltration/generator.py
def generate_data_exfiltration_scenario(output_dir: Path):
    """
    S3 data exfiltration with obfuscation.

    Attack Chain:
    1. Compromised application credentials
    2. Enumerate S3 buckets
    3. Copy to attacker-controlled bucket
    4. Use VPC endpoint to hide traffic
    5. Delete CloudTrail logs
    """
```

**Supply Chain Attack**:
```python
# generator/attack_traces/supply_chain/generator.py
def generate_supply_chain_scenario(output_dir: Path):
    """
    Compromised CI/CD pipeline.

    Attack Chain:
    1. Compromise CI/CD service account
    2. Modify build pipeline
    3. Inject malicious Lambda layer
    4. Deploy to production
    5. Establish persistence
    """
```

#### 2. Real LLM Integration

**Create** `analysis_engine/llm/providers.py`:
```python
from abc import ABC, abstractmethod
from typing import Dict, Any, List
import openai
import anthropic

class LLMProvider(ABC):
    @abstractmethod
    def generate_narrative(self, context: Dict[str, Any]) -> str:
        pass

    @abstractmethod
    def extract_iocs(self, events: List[Dict]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def plan_response(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        pass

class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model

    def generate_narrative(self, context: Dict[str, Any]) -> str:
        prompt = f"""You are a cybersecurity analyst. Generate a threat narrative from this attack data:

Events: {context['num_events']}
Kill Chain Stages: {context['kill_chain_stages']}
MITRE Techniques: {context['mitre_techniques']}
Timeline: {context['timeline']}

Provide:
1. Executive summary
2. Technical analysis
3. Impact assessment
4. Recommended actions

Be specific and actionable."""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert cybersecurity threat analyst."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
        )

        return response.choices[0].message.content

class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229"):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def generate_narrative(self, context: Dict[str, Any]) -> str:
        prompt = f"""Analyze this cloud security incident and generate a comprehensive threat report.

<context>
Total Events: {context['num_events']}
Attack Duration: {context['duration']}
Kill Chain Stages: {context['kill_chain_stages']}
MITRE ATT&CK Techniques: {context['mitre_techniques']}
Compromised Resources: {context['resources']}
</context>

<timeline>
{context['timeline']}
</timeline>

Generate a detailed report including:
1. Executive summary (2-3 sentences)
2. Attack narrative (step-by-step)
3. Impact assessment
4. IOC analysis
5. Recommended response actions"""

        message = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        return message.content[0].text

# Factory
def get_llm_provider(provider_name: str = None) -> LLMProvider:
    from config import settings

    provider = provider_name or settings.llm_provider

    if provider == "openai":
        return OpenAIProvider(settings.openai_api_key)
    elif provider == "anthropic":
        return AnthropicProvider(settings.anthropic_api_key)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
```

**Update agents to use LLM**:
```python
# analysis_engine/agents/threat_narrative_agent.py
from analysis_engine.llm.providers import get_llm_provider
from config import settings

class ThreatNarrativeAgent:
    def __init__(self, use_llm: bool = None):
        self.use_llm = use_llm if use_llm is not None else (settings.llm_provider != "none")
        if self.use_llm:
            self.llm = get_llm_provider()

    def generate_narrative(self, session, kill_chain_data, mitre_data, ioc_data):
        if self.use_llm:
            # Use real LLM
            context = self._build_context(session, kill_chain_data, mitre_data, ioc_data)
            narrative_text = self.llm.generate_narrative(context)
            return self._parse_llm_output(narrative_text)
        else:
            # Fall back to template-based
            return self._generate_template_narrative(...)
```

#### 3. Interactive SOC Dashboard (Full Implementation)

**Create** `ui/soc_dashboard/src/api/client.ts`:
```typescript
import axios, { AxiosInstance } from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000';

class APIClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': process.env.REACT_APP_API_KEY || '',
      },
    });
  }

  async listScenarios() {
    const response = await this.client.get('/scenarios');
    return response.data.scenarios;
  }

  async getScenario(name: string) {
    const response = await this.client.get(`/scenarios/${name}`);
    return response.data;
  }

  async uploadAndAnalyze(file: File) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await this.client.post('/analyze/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  }
}

export default new APIClient();
```

**Timeline Visualization** - `ui/soc_dashboard/src/components/TimelineView.tsx`:
```typescript
import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, Legend } from 'recharts';

interface TimelineEvent {
  timestamp: string;
  event_type: string;
  kill_chain_stage: string;
  description: string;
}

interface TimelineViewProps {
  events: TimelineEvent[];
}

export const TimelineView: React.FC<TimelineViewProps> = ({ events }) => {
  const stageColors = {
    reconnaissance: '#3b82f6',
    weaponization: '#8b5cf6',
    delivery: '#ec4899',
    exploitation: '#ef4444',
    installation: '#f59e0b',
    command_and_control: '#10b981',
    actions_on_objectives: '#dc2626',
  };

  // Group events by minute for visualization
  const timelineData = events.reduce((acc, event) => {
    const minute = event.timestamp.substring(0, 16); // YYYY-MM-DDTHH:MM
    if (!acc[minute]) {
      acc[minute] = { time: minute, count: 0, stages: {} };
    }
    acc[minute].count++;
    acc[minute].stages[event.kill_chain_stage] =
      (acc[minute].stages[event.kill_chain_stage] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="timeline-container">
      <h3>Attack Timeline</h3>
      <div className="timeline-events">
        {events.map((event, idx) => (
          <div key={idx} className="timeline-event">
            <div
              className="event-marker"
              style={{ backgroundColor: stageColors[event.kill_chain_stage] }}
            />
            <div className="event-details">
              <span className="event-time">{event.timestamp}</span>
              <span className="event-stage">{event.kill_chain_stage}</span>
              <span className="event-description">{event.description}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
```

**MITRE ATT&CK Heatmap** - `ui/soc_dashboard/src/components/MitreHeatmap.tsx`:
```typescript
import React from 'react';

interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  num_events: number;
}

interface MitreHeatmapProps {
  techniques: Record<string, MitreTechnique>;
}

export const MitreHeatmap: React.FC<MitreHeatmapProps> = ({ techniques }) => {
  const tactics = [
    'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
    'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact'
  ];

  const techniquesByTactic = Object.values(techniques).reduce((acc, tech) => {
    const tacticList = tech.tactic.split(',').map(t => t.trim());
    tacticList.forEach(tactic => {
      if (!acc[tactic]) acc[tactic] = [];
      acc[tactic].push(tech);
    });
    return acc;
  }, {} as Record<string, MitreTechnique[]>);

  return (
    <div className="mitre-heatmap">
      <h3>MITRE ATT&CK Coverage</h3>
      <div className="tactics-grid">
        {tactics.map(tactic => (
          <div key={tactic} className="tactic-column">
            <div className="tactic-header">{tactic}</div>
            <div className="techniques-list">
              {(techniquesByTactic[tactic] || []).map(tech => (
                <div
                  key={tech.technique_id}
                  className="technique-cell"
                  style={{
                    backgroundColor: `rgba(239, 68, 68, ${Math.min(tech.num_events / 10, 1)})`
                  }}
                  title={`${tech.technique_id}: ${tech.technique_name} (${tech.num_events} events)`}
                >
                  {tech.technique_id}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
```

#### 4. Threat Intelligence Integration

**Create** `analysis_engine/threat_intel/providers.py`:
```python
from abc import ABC, abstractmethod
import requests
from typing import Dict, List, Optional

class ThreatIntelProvider(ABC):
    @abstractmethod
    def check_ip_reputation(self, ip: str) -> Dict:
        pass

    @abstractmethod
    def check_domain_reputation(self, domain: str) -> Dict:
        pass

class AbuseIPDBProvider(ThreatIntelProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def check_ip_reputation(self, ip: str) -> Dict:
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': ''
        }

        response = requests.get(
            f"{self.base_url}/check",
            headers=headers,
            params=params
        )

        data = response.json().get('data', {})

        return {
            'ip': ip,
            'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
            'abuse_score': data.get('abuseConfidenceScore', 0),
            'country': data.get('countryCode'),
            'reports': data.get('totalReports', 0),
            'provider': 'AbuseIPDB'
        }

class VirusTotalProvider(ThreatIntelProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def check_domain_reputation(self, domain: str) -> Dict:
        headers = {'x-apikey': self.api_key}

        response = requests.get(
            f"{self.base_url}/domains/{domain}",
            headers=headers
        )

        data = response.json().get('data', {}).get('attributes', {})
        stats = data.get('last_analysis_stats', {})

        return {
            'domain': domain,
            'is_malicious': stats.get('malicious', 0) > 0,
            'malicious_count': stats.get('malicious', 0),
            'suspicious_count': stats.get('suspicious', 0),
            'reputation': data.get('reputation', 0),
            'provider': 'VirusTotal'
        }

# Enrich IOCs with threat intelligence
class IOCEnricher:
    def __init__(self, providers: List[ThreatIntelProvider]):
        self.providers = providers

    def enrich_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        enriched = {}

        # Enrich IPs
        if 'ip_addresses' in iocs:
            enriched['ip_addresses'] = []
            for ip in iocs['ip_addresses']:
                ip_data = {'value': ip, 'intelligence': []}
                for provider in self.providers:
                    try:
                        intel = provider.check_ip_reputation(ip)
                        ip_data['intelligence'].append(intel)
                    except Exception as e:
                        logger.error(f"Failed to check {ip} with {provider}: {e}")
                enriched['ip_addresses'].append(ip_data)

        # Enrich domains
        if 'domains' in iocs:
            enriched['domains'] = []
            for domain in iocs['domains']:
                domain_data = {'value': domain, 'intelligence': []}
                for provider in self.providers:
                    try:
                        intel = provider.check_domain_reputation(domain)
                        domain_data['intelligence'].append(intel)
                    except Exception as e:
                        logger.error(f"Failed to check {domain} with {provider}: {e}")
                enriched['domains'].append(domain_data)

        return enriched
```

#### 5. Automated Testing & CI/CD

**Create** `.github/workflows/ci.yml`:
```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12']

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-cov

    - name: Run tests with coverage
      run: |
        pytest --cov=generator --cov=analysis_engine --cov-report=xml

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml

    - name: Lint with flake8
      run: |
        pip install flake8
        flake8 generator analysis_engine --max-line-length=100

    - name: Type check with mypy
      run: |
        pip install mypy
        mypy generator analysis_engine

    - name: Security scan
      run: |
        pip install bandit
        bandit -r generator analysis_engine

  integration:
    runs-on: ubuntu-latest
    needs: test

    steps:
    - uses: actions/checkout@v3

    - name: Build Docker images
      run: docker-compose build

    - name: Start services
      run: docker-compose up -d

    - name: Wait for services
      run: sleep 30

    - name: Run integration tests
      run: |
        python -m pip install requests
        python tests/integration/test_api.py

    - name: Check service health
      run: |
        curl -f http://localhost:8000/health || exit 1

    - name: Cleanup
      run: docker-compose down

  scenario-validation:
    runs-on: ubuntu-latest
    needs: test

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        pip install -r requirements.txt

    - name: Run all scenarios
      run: |
        ./scripts/run_all_scenarios.sh

    - name: Validate telemetry
      run: |
        for scenario in output/scenarios/*; do
          python cli/validate_traces.py "$scenario/telemetry.jsonl"
        done

    - name: Upload scenario artifacts
      uses: actions/upload-artifact@v3
      with:
        name: scenario-outputs
        path: output/scenarios/
```

#### 6. Performance Monitoring & Metrics

**Create** `analysis_engine/monitoring/metrics.py`:
```python
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from functools import wraps
import time

# Metrics
analysis_requests_total = Counter(
    'analysis_requests_total',
    'Total analysis requests',
    ['scenario', 'status']
)

analysis_duration_seconds = Histogram(
    'analysis_duration_seconds',
    'Analysis duration in seconds',
    ['scenario']
)

events_processed_total = Counter(
    'events_processed_total',
    'Total events processed',
    ['event_source']
)

sessions_detected_total = Counter(
    'sessions_detected_total',
    'Total sessions detected',
    ['is_malicious']
)

current_analysis_jobs = Gauge(
    'current_analysis_jobs',
    'Number of currently running analysis jobs'
)

def track_analysis(func):
    """Decorator to track analysis metrics."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        current_analysis_jobs.inc()
        start_time = time.time()

        try:
            result = func(*args, **kwargs)

            # Track success metrics
            scenario = kwargs.get('scenario', 'unknown')
            analysis_requests_total.labels(scenario=scenario, status='success').inc()

            duration = time.time() - start_time
            analysis_duration_seconds.labels(scenario=scenario).observe(duration)

            return result

        except Exception as e:
            scenario = kwargs.get('scenario', 'unknown')
            analysis_requests_total.labels(scenario=scenario, status='error').inc()
            raise

        finally:
            current_analysis_jobs.dec()

    return wrapper

# Add metrics endpoint to API
@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

#### 7. Advanced Correlation Algorithms

**Create** `analysis_engine/core/graph_correlation.py`:
```python
import networkx as nx
from typing import List, Dict, Set
from .parser import NormalizedEvent
from .correlation import CorrelationSession

class GraphCorrelator:
    """
    Graph-based correlation for complex attack patterns.

    Builds a graph where:
    - Nodes: Principals, IPs, Resources
    - Edges: Events connecting them

    Detects attack campaigns across multiple sessions.
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_attack_graph(self, events: List[NormalizedEvent]) -> nx.DiGraph:
        """Build graph from events."""
        for event in events:
            # Add nodes
            if event.principal:
                self.graph.add_node(
                    event.principal,
                    node_type='principal',
                    first_seen=event.timestamp
                )

            if event.source_ip:
                self.graph.add_node(
                    event.source_ip,
                    node_type='ip',
                    first_seen=event.timestamp
                )

            if event.resource:
                self.graph.add_node(
                    event.resource,
                    node_type='resource',
                    first_seen=event.timestamp
                )

            # Add edges
            if event.principal and event.resource:
                self.graph.add_edge(
                    event.principal,
                    event.resource,
                    event_type=event.event_type,
                    timestamp=event.timestamp,
                    action=event.action
                )

            if event.source_ip and event.principal:
                self.graph.add_edge(
                    event.source_ip,
                    event.principal,
                    event_type='authentication',
                    timestamp=event.timestamp
                )

        return self.graph

    def detect_attack_campaigns(self) -> List[Set[str]]:
        """
        Detect attack campaigns using community detection.

        Returns groups of related nodes (potential campaigns).
        """
        # Remove node types temporarily for community detection
        undirected = self.graph.to_undirected()

        # Use Louvain community detection
        from networkx.algorithms import community
        communities = community.louvain_communities(undirected)

        return [set(c) for c in communities]

    def find_pivot_points(self) -> List[str]:
        """
        Find pivot points (nodes used for lateral movement).

        Identifies nodes with high betweenness centrality.
        """
        centrality = nx.betweenness_centrality(self.graph)

        # Return nodes with centrality > threshold
        threshold = 0.5
        pivots = [
            node for node, score in centrality.items()
            if score > threshold
        ]

        return pivots

    def trace_attack_path(self, start_node: str, end_node: str) -> List[str]:
        """Find shortest attack path between two nodes."""
        try:
            path = nx.shortest_path(self.graph, start_node, end_node)
            return path
        except nx.NetworkXNoPath:
            return []
```

---

## SUMMARY: VERSION COMPARISON

### v1.0 (Current)
- Basic telemetry generation
- Template-based analysis
- 3 attack scenarios
- CLI interface
- Basic UI skeleton

### v2.0 (Enhancements)
- ✅ Proper package structure
- ✅ Configuration management
- ✅ API security & rate limiting
- ✅ Database persistence
- ✅ Streaming for large files
- ✅ Bug fixes

### v3.0 (Advanced)
- ✅ 6+ attack scenarios
- ✅ Real LLM integration
- ✅ Full SOC dashboard UI
- ✅ Threat intelligence feeds
- ✅ Graph-based correlation
- ✅ CI/CD pipeline
- ✅ Performance monitoring
- ✅ Advanced analytics

---

## IMPLEMENTATION PRIORITY

### Phase 1: Critical Fixes (Week 1)
1. Fix Python compatibility
2. Add missing __init__.py files
3. Fix CORS security
4. Fix timestamp distribution
5. Fix file descriptor leaks

### Phase 2: Core Improvements (Weeks 2-3)
1. Proper package structure (setup.py)
2. Configuration management
3. API security layer
4. Expand test coverage
5. Database persistence

### Phase 3: Feature Expansion (Weeks 4-6)
1. Add 3 new attack scenarios
2. LLM integration framework
3. Implement full UI components
4. Threat intel integration
5. Graph correlation

### Phase 4: Production Readiness (Weeks 7-8)
1. CI/CD pipeline
2. Performance monitoring
3. Documentation updates
4. Security audit
5. Load testing

---

## ESTIMATED EFFORT

- **v1.1 Patch**: 1-2 days
- **v2.0 Release**: 3-4 weeks
- **v3.0 Release**: 6-8 weeks

Total: ~2.5 months to v3.0 production-ready
