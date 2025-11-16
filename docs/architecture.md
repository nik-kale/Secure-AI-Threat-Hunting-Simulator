# Architecture

## System Overview

The AI Threat Hunting Simulator is built as a modular, pipeline-based architecture with three primary components:

```
┌─────────────────────────────────────────────────────────────┐
│                  AI THREAT HUNTING SIMULATOR                 │
└─────────────────────────────────────────────────────────────┘

┌──────────────────┐      ┌──────────────────┐      ┌─────────────┐
│   GENERATOR      │─────▶│ ANALYSIS ENGINE  │─────▶│  UI/REPORTS │
│                  │      │                  │      │             │
│ • Synthesizer    │      │ • Parser         │      │ • Dashboard │
│ • Attack Traces  │      │ • Correlator     │      │ • CLI       │
│ • Topologies     │      │ • Mappers        │      │ • Reports   │
│ • Schemas        │      │ • AI Agents      │      │             │
└──────────────────┘      └──────────────────┘      └─────────────┘
```

## Component Architecture

### 1. Telemetry Generator

**Purpose:** Generate realistic synthetic cloud attack telemetry

**Structure:**
```
generator/
├── telemetry_synthesizer.py    # Core event generator
├── attack_traces/               # Scenario-specific generators
│   ├── iam_priv_escalation/
│   ├── container_escape/
│   └── cred_stuffing/
├── cloud_topologies/            # Environment definitions
├── schemas/                     # Data schemas
└── utils/                       # Helper functions
```

**Key Classes:**
- `TelemetrySynthesizer`: Main class for generating events
  - Creates CloudTrail-like events
  - Generates IAM, S3, Lambda, container, network events
  - Adds realistic benign noise

**Output:** JSONL files with synthetic telemetry events

### 2. Analysis Engine

**Purpose:** AI-assisted correlation, mapping, and narrative generation

**Structure:**
```
analysis_engine/
├── pipeline.py                  # Main orchestrator
├── core/
│   ├── loader.py                # Load telemetry
│   ├── parser.py                # Normalize events
│   ├── correlation.py           # Session building
│   ├── kill_chain.py            # Kill chain mapper
│   └── mitre_mapper.py          # MITRE ATT&CK mapper
├── agents/
│   ├── ioc_extractor_agent.py   # Extract IOCs
│   ├── threat_narrative_agent.py # Generate narratives
│   └── response_planner_agent.py # IR planning
├── reports/
│   ├── json_reporter.py
│   └── markdown_reporter.py
└── api/
    └── server.py                # FastAPI server
```

**Analysis Pipeline Flow:**

```
1. Load Telemetry
   ↓
2. Parse & Normalize Events
   ↓
3. Correlate into Sessions
   ├─ By Session ID
   ├─ By Principal
   └─ By Source IP
   ↓
4. Identify Suspicious Sessions (risk scoring)
   ↓
5. For Each Suspicious Session:
   ├─ Map to Kill Chain Stages
   ├─ Map to MITRE ATT&CK Techniques
   ├─ Extract IOCs
   ├─ Generate Threat Narrative
   └─ Create Response Plan
   ↓
6. Generate Reports (JSON, Markdown)
```

**Key Classes:**

- `ThreatHuntingPipeline`: Main orchestrator
- `EventCorrelator`: Groups events into sessions
- `KillChainMapper`: Maps to Cyber Kill Chain
- `MitreMapper`: Maps to MITRE ATT&CK
- `IocExtractorAgent`: Extracts indicators
- `ThreatNarrativeAgent`: Generates narratives
- `ResponsePlannerAgent`: Creates IR plans

### 3. User Interfaces

**CLI Tools:**
- `cli/run_scenario.py`: Run scenarios end-to-end
- `cli/validate_traces.py`: Validate telemetry schema

**API Server:**
- FastAPI-based REST API
- Endpoints for analysis, scenario management
- CORS-enabled for UI integration

**SOC Dashboard (UI):**
- React/TypeScript application
- Timeline visualization
- Attack graph display
- MITRE ATT&CK heatmap
- IOC tables
- Response plan viewer

## Data Flow

### Event Schema

All events follow a common schema:

```json
{
  "event_id": "uuid",
  "timestamp": "ISO 8601",
  "event_type": "service.action",
  "event_source": "service",
  "account_id": "12-digit",
  "region": "us-east-1",
  "principal": "ARN",
  "source_ip": "IP address",
  "user_agent": "string",
  "action": "Action",
  "status": "success|failure",
  "metadata": {}
}
```

### Session Model

Correlated events form sessions:

```python
CorrelationSession:
  - session_id
  - events: List[NormalizedEvent]
  - principals: Set[str]
  - source_ips: Set[str]
  - resources: Set[str]
  - start_time, end_time
  - attack_stages: Set[str]
  - mitre_techniques: Set[str]
  - risk_score: float
```

## AI Agent Architecture

The analysis engine uses a "simulated AI" approach with clearly marked integration points:

```python
# Current: Template-based logic
def generate_narrative(context):
    # Deterministic template-based generation
    return narrative

# Future: LLM integration at marked points
# LLM_INTEGRATION_POINT
def generate_narrative(context):
    response = llm.complete(prompt)
    return response
```

**Benefits:**
- Deterministic and reproducible for testing
- No external API dependencies
- Clear upgrade path to real LLM integration
- Educational value (shows reasoning logic)

## Deployment Architecture

### Docker Compose Setup

```yaml
services:
  analysis-engine:
    - FastAPI application
    - Port 8000
    - Volumes for telemetry/reports

  soc-dashboard:
    - React UI
    - Port 3000
    - Connects to analysis-engine API
```

### Local Development

```bash
# Run generator
python cli/run_scenario.py --scenario iam_priv_escalation --output ./output

# Run analysis engine API
python -m uvicorn analysis_engine.api.server:app

# Run UI (development mode)
cd ui/soc_dashboard && npm start
```

## Extensibility Points

### 1. Add New Attack Scenarios

```python
# generator/attack_traces/my_attack/generator.py
def generate_my_attack_scenario(output_dir, ...):
    synthesizer = TelemetrySynthesizer(...)
    events = []
    # Generate attack events
    synthesizer.write_events_jsonl(events, output_path)
```

### 2. Add Custom Correlation Logic

```python
# analysis_engine/core/correlation.py
class EventCorrelator:
    def correlate_by_custom_criteria(self, events):
        # Custom correlation logic
        pass
```

### 3. Integrate Real LLM

```python
# analysis_engine/agents/threat_narrative_agent.py
import openai

def generate_narrative(self, context):
    # LLM_INTEGRATION_POINT
    response = openai.ChatCompletion.create(...)
    return response
```

### 4. Add New Event Sources

```python
# generator/telemetry_synthesizer.py
class TelemetrySynthesizer:
    def create_guardduty_event(self, ...):
        # Generate GuardDuty-style events
        pass
```

## Security Considerations

### Data Safety

- **All synthetic data**: No real credentials, IPs, or customer data
- **Local processing**: No external API calls (except optional LLM)
- **Sandboxed execution**: Scenarios run in isolated environments

### Safe Defaults

- Account IDs: Synthetic (123456789012)
- IP addresses: RFC 1918 or clearly synthetic
- API keys: Fake format (AKIA...)
- ARNs: Synthetic resource names

## Performance

### Telemetry Generation

- **Speed**: ~1000 events/second
- **Memory**: Minimal (streaming JSONL)
- **Storage**: ~1KB per event (JSONL)

### Analysis Pipeline

- **Throughput**: Analyzes ~10,000 events in ~5 seconds
- **Memory**: Scales linearly with event count
- **Bottlenecks**: Correlation for very large datasets

### Optimization Strategies

1. **Streaming processing** for large telemetry files
2. **Batch correlation** for high-volume scenarios
3. **Caching** for repeated analysis
4. **Parallel processing** for multiple sessions

## Testing Strategy

### Unit Tests

- Schema validation
- Event generation
- Correlation logic
- Kill chain mapping
- MITRE mapping

### Integration Tests

- End-to-end scenario execution
- Pipeline execution
- API endpoint testing

### Validation

- Schema compliance checking
- Output format verification
- Reproducibility testing
