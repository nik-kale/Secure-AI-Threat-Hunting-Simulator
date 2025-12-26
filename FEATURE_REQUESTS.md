# Feature Requests: AI Threat Hunting Simulator

**Generated:** 2025-12-26
**Analysis Version:** 6.0.0
**Analyst:** Senior Software Architect

---

## Summary Table

| # | Feature | Category | Effort | Value | Priority Score |
|---|---------|----------|--------|-------|----------------|
| 1 | Fix Broken Attack Scenarios | Functional | Low | High | 3.0 |
| 2 | Expand Unit Test Coverage | Architecture | Medium | High | 1.5 |
| 3 | Add OpenTelemetry Distributed Tracing | Observability | Medium | High | 1.5 |
| 4 | Implement API Request Timeout & Circuit Breaker | Code Quality | Low | Medium | 2.0 |
| 5 | Add API Key Brute Force Protection | Security | Low | High | 3.0 |
| 6 | Create Interactive CLI with Progress Indicators | Developer Experience | Low | Medium | 2.0 |
| 7 | Add PDF/HTML Report Export | Functional | Medium | Medium | 1.0 |
| 8 | Implement Background Job Queue for Long Analyses | Architecture | High | High | 1.0 |
| 9 | Add Scenario Builder/Customization API | Functional | Medium | High | 1.5 |
| 10 | Create Jupyter Notebook Tutorials | Documentation | Low | Medium | 2.0 |

**Priority Score Formula:** Value ÷ Effort (High=3, Medium=2, Low=1)

---

## Detailed Feature Requests

---

### Feature #1: Fix Broken Attack Scenarios

**Category:** Functional Enhancement
**Effort:** Low | **Value:** High | **Priority Score:** 3.0

#### Problem Statement

Three of the six core attack scenarios (`lateral_movement`, `data_exfiltration`, `supply_chain`) are non-functional due to missing telemetry synthesizer methods. This blocks 50% of the project's core value proposition - users cannot practice threat hunting on half of the available attack patterns.

#### Proposed Solution

- [ ] Add `create_sts_event()` method to `TelemetrySynthesizer` for STS AssumeRole events
- [ ] Add `create_database_event()` method for RDS/DynamoDB event generation
- [ ] Add `create_codecommit_event()` and `create_codepipeline_event()` for CI/CD scenarios
- [ ] Validate all three scenarios generate valid JSONL output
- [ ] Add integration tests for each fixed scenario

#### Implementation Details

**File:** `generator/telemetry_synthesizer.py`

```python
def create_sts_event(
    self,
    action: str,  # AssumeRole, GetSessionToken, etc.
    principal: str,
    role_arn: str,
    timestamp: str,
    source_ip: str = None,
    duration_seconds: int = 3600,
    status: str = "success"
) -> Dict[str, Any]:
    """Generate STS (Security Token Service) event."""
    pass

def create_database_event(
    self,
    service: str,  # "rds" or "dynamodb"
    action: str,  # CreateDBSnapshot, Query, Scan, etc.
    principal: str,
    resource_arn: str,
    timestamp: str,
    status: str = "success"
) -> Dict[str, Any]:
    """Generate RDS/DynamoDB event."""
    pass
```

#### Success Metrics

- All 6 scenarios generate valid telemetry without errors
- CI pipeline `test-scenarios` job passes for all scenarios
- Each scenario produces minimum expected event count
- Analysis pipeline successfully processes all scenario outputs

---

### Feature #2: Expand Unit Test Coverage

**Category:** Architecture & Scalability
**Effort:** Medium | **Value:** High | **Priority Score:** 1.5

#### Problem Statement

Current test coverage is estimated at <10% with only 612 lines of test code across 3 test files. This creates significant maintenance risk and makes refactoring dangerous. Critical components like the ML pipeline, SIEM exporters, and API endpoints have zero test coverage.

#### Proposed Solution

- [ ] Create test fixtures for common telemetry data patterns
- [ ] Add unit tests for `analysis_engine/ml/` module (anomaly detector, behavioral baseline)
- [ ] Add unit tests for `analysis_engine/integrations/` (SIEM exporters)
- [ ] Add API integration tests using `httpx` and `pytest-asyncio`
- [ ] Configure pytest-cov to fail below 40% coverage threshold

#### Implementation Details

**New Files:**
```
tests/
├── conftest.py                    # Shared fixtures
├── fixtures/
│   ├── telemetry_samples.py       # Sample event data
│   └── scenario_outputs.py        # Expected analysis outputs
├── test_ml_anomaly_detector.py
├── test_ml_behavioral_baseline.py
├── test_siem_exporters.py
├── test_api_endpoints.py
└── test_detection_rules.py
```

**Example fixture:**
```python
# tests/conftest.py
import pytest
from datetime import datetime

@pytest.fixture
def sample_iam_events():
    """Sample IAM privilege escalation events."""
    return [
        {"event_type": "iam.CreateRole", "timestamp": "2025-01-01T00:00:00Z", ...},
        # ... more events
    ]
```

#### Success Metrics

- Test coverage increases from <10% to 40%+
- All critical paths have at least one test
- CI pipeline includes coverage gate
- No regressions in existing functionality

---

### Feature #3: Add OpenTelemetry Distributed Tracing

**Category:** Observability Stack
**Effort:** Medium | **Value:** High | **Priority Score:** 1.5

#### Problem Statement

While the project has good logging and Prometheus metrics, there's no distributed tracing support. This makes debugging complex analysis pipelines difficult, especially when LLM calls or threat intelligence enrichment adds latency. Users deploying in production cannot trace requests across the generator → API → analysis → database flow.

#### Proposed Solution

- [ ] Add `opentelemetry-api` and `opentelemetry-sdk` to requirements.txt
- [ ] Create tracing initialization module with configurable exporters (Jaeger, OTLP)
- [ ] Instrument FastAPI with `opentelemetry-instrumentation-fastapi`
- [ ] Add custom spans for pipeline stages (correlation, MITRE mapping, narrative generation)
- [ ] Propagate trace context through WebSocket connections

#### Implementation Details

**New File:** `analysis_engine/monitoring/tracing.py`

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

def init_tracing(service_name: str = "threat-hunting-simulator"):
    """Initialize OpenTelemetry tracing."""
    provider = TracerProvider()

    if os.getenv("OTEL_EXPORTER_ENDPOINT"):
        exporter = OTLPSpanExporter(endpoint=os.getenv("OTEL_EXPORTER_ENDPOINT"))
        provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)
```

**Configuration additions to `config.py`:**
```python
# OpenTelemetry
otel_enabled: bool = Field(False, env="OTEL_ENABLED")
otel_exporter_endpoint: Optional[str] = Field(None, env="OTEL_EXPORTER_ENDPOINT")
otel_service_name: str = Field("threat-hunting-simulator", env="OTEL_SERVICE_NAME")
```

#### Success Metrics

- Traces visible in Jaeger/Tempo for API requests
- Pipeline stages (load → parse → correlate → map → generate) appear as nested spans
- LLM and threat intel calls show accurate latency
- Trace IDs correlate with existing request IDs

---

### Feature #4: Implement API Request Timeout & Circuit Breaker

**Category:** Code Quality & Optimization
**Effort:** Low | **Value:** Medium | **Priority Score:** 2.0

#### Problem Statement

The API has no timeout protection for long-running analysis operations. A large file upload or complex scenario could hang indefinitely, consuming server resources. There's also no circuit breaker for external dependencies (LLM APIs, threat intelligence), meaning one slow provider can cascade failures.

#### Proposed Solution

- [ ] Add configurable request timeout middleware (default: 5 minutes for analysis)
- [ ] Implement circuit breaker pattern for LLM provider calls
- [ ] Add circuit breaker for threat intelligence API calls
- [ ] Create health degradation when circuit opens
- [ ] Add timeout configuration to Settings

#### Implementation Details

**Add to `analysis_engine/api/server.py`:**
```python
from starlette.middleware.base import BaseHTTPMiddleware
import asyncio

class TimeoutMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, timeout_seconds: int = 300):
        super().__init__(app)
        self.timeout = timeout_seconds

    async def dispatch(self, request, call_next):
        try:
            return await asyncio.wait_for(
                call_next(request),
                timeout=self.timeout
            )
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=504,
                content={"error": "Request timeout", "timeout_seconds": self.timeout}
            )
```

**New File:** `analysis_engine/resilience/circuit_breaker.py`
```python
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failures = 0
        self.threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = "closed"
        self.last_failure_time = None
```

#### Success Metrics

- No request hangs longer than configured timeout
- Circuit opens after N consecutive LLM failures
- Health endpoint reflects circuit state
- Graceful degradation when LLM unavailable (fallback to templates)

---

### Feature #5: Add API Key Brute Force Protection

**Category:** Security Posture
**Effort:** Low | **Value:** High | **Priority Score:** 3.0

#### Problem Statement

The current API key validation has no protection against brute force attacks. An attacker could enumerate API keys by making unlimited authentication attempts. Combined with the rate limiter (which uses IP), this leaves a gap for distributed attacks.

#### Proposed Solution

- [ ] Implement exponential backoff on failed API key attempts per IP
- [ ] Add account lockout after N failed attempts (configurable, default: 10)
- [ ] Log security events for failed authentication attempts
- [ ] Add IP-based temporary ban after excessive failures
- [ ] Create admin endpoint to view/clear lockouts

#### Implementation Details

**Update `analysis_engine/api/auth.py`:**
```python
from collections import defaultdict
from datetime import datetime, timedelta
import time

# Track failed attempts per IP
failed_attempts: Dict[str, List[float]] = defaultdict(list)
locked_ips: Dict[str, float] = {}

LOCKOUT_THRESHOLD = 10
LOCKOUT_DURATION = 900  # 15 minutes
ATTEMPT_WINDOW = 300    # 5 minute sliding window

async def verify_api_key_with_protection(
    request: Request,
    api_key: str = Security(api_key_header)
):
    client_ip = get_client_ip(request)

    # Check if IP is locked
    if client_ip in locked_ips:
        if time.time() < locked_ips[client_ip]:
            AuditLogger.log_security_event(
                "blocked_request",
                request_id=getattr(request.state, 'request_id', 'unknown'),
                description=f"Blocked request from locked IP: {client_ip}",
                client_ip=client_ip,
                severity="WARNING"
            )
            raise HTTPException(
                status_code=429,
                detail="Too many failed attempts. Try again later."
            )
        else:
            del locked_ips[client_ip]

    # Verify API key
    result = await verify_api_key(api_key)

    if result is None and os.getenv("API_KEY"):  # Key was wrong
        _record_failed_attempt(client_ip)

    return result

def _record_failed_attempt(ip: str):
    now = time.time()
    # Clean old attempts outside window
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < ATTEMPT_WINDOW]
    failed_attempts[ip].append(now)

    if len(failed_attempts[ip]) >= LOCKOUT_THRESHOLD:
        locked_ips[ip] = now + LOCKOUT_DURATION
        AuditLogger.log_security_event(...)
```

#### Success Metrics

- Brute force attempts result in temporary lockout
- Security events logged for all failed attempts
- No false positives for legitimate users
- Admin can view/clear lockouts via API

---

### Feature #6: Create Interactive CLI with Progress Indicators

**Category:** Developer Experience
**Effort:** Low | **Value:** Medium | **Priority Score:** 2.0

#### Problem Statement

The current CLI provides minimal feedback during long-running operations. Users analyzing large telemetry files see no progress indication, making it unclear if the tool is working or stuck. This creates a poor user experience and makes debugging difficult.

#### Proposed Solution

- [ ] Add `rich` library for enhanced terminal output
- [ ] Implement progress bars for file processing with event counts
- [ ] Add spinner for LLM and threat intel API calls
- [ ] Create colored output for different log levels (info, warning, error)
- [ ] Add `--verbose` flag for detailed output and `--quiet` for minimal output

#### Implementation Details

**Update `requirements.txt`:**
```
rich>=13.0.0
```

**Update `cli/analyze.py`:**
```python
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel

console = Console()

@click.command()
@click.argument('telemetry_file', type=click.Path(exists=True))
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def analyze(telemetry_file: str, verbose: bool):
    """Analyze telemetry file for threats."""

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:

        # Loading phase
        load_task = progress.add_task("Loading telemetry...", total=100)
        events = load_events(telemetry_file, progress, load_task)

        # Analysis phase
        analyze_task = progress.add_task("Analyzing events...", total=len(events))
        for event in events:
            process_event(event)
            progress.update(analyze_task, advance=1)

    # Summary panel
    console.print(Panel.fit(
        f"[green]✓ Analysis Complete[/green]\n"
        f"Events: {len(events)}\n"
        f"Sessions: {session_count}\n"
        f"Suspicious: {suspicious_count}",
        title="Results"
    ))
```

#### Success Metrics

- Users see real-time progress during analysis
- Long operations (>5s) show spinner or progress bar
- Error messages clearly distinguishable from info
- CLI feels responsive and professional

---

### Feature #7: Add PDF/HTML Report Export

**Category:** Functional Enhancement
**Effort:** Medium | **Value:** Medium | **Priority Score:** 1.0

#### Problem Statement

Currently, analysis reports are only available in JSON and Markdown formats. Security teams often need polished PDF reports for executives or compliance audits. The lack of export options limits the tool's usefulness in enterprise environments.

#### Proposed Solution

- [ ] Add `weasyprint` or `reportlab` for PDF generation
- [ ] Create HTML report template with CSS styling
- [ ] Add PDF export to CLI (`--format pdf`)
- [ ] Add API endpoint for report format conversion
- [ ] Include charts/graphs in visual reports (timeline, kill chain coverage)

#### Implementation Details

**New File:** `analysis_engine/reports/pdf_generator.py`
```python
from weasyprint import HTML, CSS
from jinja2 import Environment, FileSystemLoader

class PDFReportGenerator:
    def __init__(self, template_dir: Path = None):
        self.template_dir = template_dir or Path(__file__).parent / "templates"
        self.env = Environment(loader=FileSystemLoader(self.template_dir))

    def generate(self, analysis_result: Dict, output_path: Path) -> Path:
        """Generate PDF report from analysis results."""
        template = self.env.get_template("report.html")
        html_content = template.render(
            title="Threat Analysis Report",
            timestamp=datetime.now().isoformat(),
            **analysis_result
        )

        HTML(string=html_content).write_pdf(
            output_path,
            stylesheets=[CSS(self.template_dir / "report.css")]
        )
        return output_path
```

**Report template structure:**
```
analysis_engine/reports/templates/
├── report.html
├── report.css
├── partials/
│   ├── header.html
│   ├── timeline.html
│   ├── iocs.html
│   └── mitre_coverage.html
└── assets/
    └── logo.png
```

#### Success Metrics

- PDF reports render correctly with styling
- Reports include all key analysis data
- Charts/timeline visualizations included
- File size reasonable (<5MB for typical report)

---

### Feature #8: Implement Background Job Queue for Long Analyses

**Category:** Architecture & Scalability
**Effort:** High | **Value:** High | **Priority Score:** 1.0

#### Problem Statement

Large telemetry files (100MB+) can take several minutes to analyze, blocking API workers and risking timeout. There's no way to submit a job and check status later. This limits scalability and creates poor UX for large files.

#### Proposed Solution

- [ ] Add Celery or RQ (Redis Queue) for background job processing
- [ ] Create `/jobs` API endpoints for job submission and status polling
- [ ] Add job status tracking in Redis or database
- [ ] Implement WebSocket notifications for job completion
- [ ] Add CLI option for async analysis with polling

#### Implementation Details

**New Files:**
```
analysis_engine/jobs/
├── __init__.py
├── worker.py
├── tasks.py
└── models.py
```

**`analysis_engine/jobs/tasks.py`:**
```python
from celery import Celery
from analysis_engine.pipeline import ThreatHuntingPipeline

celery = Celery('analysis_jobs', broker=os.getenv('REDIS_URL'))

@celery.task(bind=True)
def analyze_file_async(self, file_path: str, options: dict):
    """Async file analysis task."""
    self.update_state(state='PROCESSING', meta={'progress': 0})

    pipeline = ThreatHuntingPipeline(**options)

    # Stream progress updates
    for progress in pipeline.analyze_with_progress(file_path):
        self.update_state(state='PROCESSING', meta={'progress': progress})

    return pipeline.get_results()
```

**API Endpoints:**
```python
@app.post("/jobs/analyze")
async def submit_analysis_job(file: UploadFile) -> Dict:
    """Submit async analysis job."""
    task = analyze_file_async.delay(saved_path, options)
    return {"job_id": task.id, "status": "queued"}

@app.get("/jobs/{job_id}")
async def get_job_status(job_id: str) -> Dict:
    """Get job status and results."""
    task = analyze_file_async.AsyncResult(job_id)
    return {"job_id": job_id, "status": task.status, "result": task.result}
```

#### Success Metrics

- Files >50MB process in background without blocking API
- Job status accurately reflects progress
- Results retrievable after completion
- Failed jobs show clear error messages

---

### Feature #9: Add Scenario Builder/Customization API

**Category:** Functional Enhancement
**Effort:** Medium | **Value:** High | **Priority Score:** 1.5

#### Problem Statement

Users can only run pre-built attack scenarios. There's no way to customize scenarios (change timing, add more events, combine attack patterns) without modifying Python code. This limits the tool's flexibility for training exercises and detection rule testing.

#### Proposed Solution

- [ ] Create scenario definition schema (YAML-based)
- [ ] Add API endpoint for custom scenario generation
- [ ] Implement scenario composition (combine multiple attack patterns)
- [ ] Add parameter customization (accounts, regions, timing, intensity)
- [ ] Create scenario validation before generation

#### Implementation Details

**Scenario Schema (`generator/schemas/scenario.yaml`):**
```yaml
# Example custom scenario definition
name: "custom_attack_chain"
description: "Combined IAM escalation and data exfiltration"
duration_hours: 4
noise_ratio: 0.4

stages:
  - type: iam_priv_escalation
    start_offset_minutes: 0
    config:
      principal: "arn:aws:iam::123456789012:user/attacker"
      target_role: "AdminRole"

  - type: data_exfiltration
    start_offset_minutes: 60
    depends_on: iam_priv_escalation
    config:
      source_bucket: "sensitive-data"
      exfil_method: "s3_copy"
```

**API Endpoint:**
```python
@app.post("/scenarios/generate")
async def generate_custom_scenario(
    request: Request,
    scenario_def: ScenarioDefinition
) -> Dict:
    """Generate custom scenario from definition."""
    validator = ScenarioValidator()
    validator.validate(scenario_def)

    generator = CompositeScenarioGenerator()
    events = generator.generate(scenario_def)

    return {"scenario_id": scenario_id, "event_count": len(events)}
```

#### Success Metrics

- Custom scenarios generate valid telemetry
- Schema validation catches errors before generation
- Multi-stage scenarios maintain realistic timing
- Generated events pass existing analysis pipeline

---

### Feature #10: Create Jupyter Notebook Tutorials

**Category:** Documentation & Developer Experience
**Effort:** Low | **Value:** Medium | **Priority Score:** 2.0

#### Problem Statement

Despite comprehensive documentation, there's no interactive learning path for new users. The learning curve is steep for users unfamiliar with threat hunting concepts. Jupyter notebooks would provide hands-on tutorials that combine explanation with executable examples.

#### Proposed Solution

- [ ] Create "Getting Started" notebook with basic scenario generation and analysis
- [ ] Create "Detection Rule Development" notebook for Sigma rule testing
- [ ] Create "ML Anomaly Detection" notebook explaining the behavioral baseline
- [ ] Create "MITRE ATT&CK Mapping" notebook with visualization
- [ ] Add notebooks to documentation and quickstart guide

#### Implementation Details

**New Files:**
```
notebooks/
├── 01_getting_started.ipynb
├── 02_understanding_attack_scenarios.ipynb
├── 03_writing_detection_rules.ipynb
├── 04_ml_anomaly_detection.ipynb
├── 05_mitre_attack_mapping.ipynb
└── data/
    └── sample_telemetry.jsonl
```

**Example notebook structure (`01_getting_started.ipynb`):**
```markdown
# Getting Started with AI Threat Hunting Simulator

## 1. Introduction
- What is threat hunting?
- Why synthetic data?

## 2. Generating Your First Attack Scenario
```python
from generator.attack_traces.iam_priv_escalation import generate_scenario
events = generate_scenario()
print(f"Generated {len(events)} events")
```

## 3. Analyzing the Telemetry
```python
from analysis_engine.pipeline import ThreatHuntingPipeline
pipeline = ThreatHuntingPipeline()
results = pipeline.analyze(events)
```

## 4. Understanding the Results
[Visualization of timeline, kill chain, IOCs]

## 5. Next Steps
- Try different scenarios
- Write your first detection rule
```

#### Success Metrics

- New users complete "Getting Started" in <30 minutes
- Notebooks run without errors on fresh install
- Notebooks referenced in README quickstart
- Positive user feedback on learning experience

---

## Implementation Roadmap

### Phase 1: Quick Wins (Week 1)
1. **#1 Fix Broken Attack Scenarios** - Unblock 50% of core functionality
2. **#5 API Key Brute Force Protection** - Critical security gap
3. **#6 Interactive CLI** - Immediate UX improvement

### Phase 2: Quality & Observability (Week 2-3)
4. **#2 Expand Unit Test Coverage** - Enable safe refactoring
5. **#3 OpenTelemetry Tracing** - Production observability
6. **#4 Timeout & Circuit Breaker** - Resilience improvement

### Phase 3: Features & Polish (Week 4-5)
7. **#10 Jupyter Tutorials** - Onboarding improvement
8. **#9 Scenario Builder API** - Power user feature
9. **#7 PDF Report Export** - Enterprise requirement
10. **#8 Background Job Queue** - Scalability (largest effort)

---

## Appendix: Competitive Analysis

### Compared Projects

1. **Atomic Red Team** - Focus on execution, not detection training
2. **MITRE Caldera** - Full adversary simulation, more complex
3. **Detection Lab** - VM-based, heavier infrastructure

### Differentiators for This Project

- **Synthetic data focus** - Safe for any environment
- **AI-assisted narratives** - Unique LLM integration
- **Multi-cloud coverage** - AWS, Azure, GCP in single tool
- **Detection rule testing** - Built-in Sigma validation

### Feature Gaps vs. Competitors

| Feature | This Project | Atomic Red | Caldera |
|---------|--------------|------------|---------|
| Synthetic telemetry | ✅ | ❌ | ❌ |
| LLM narratives | ✅ | ❌ | ❌ |
| Sigma rule testing | ✅ | ❌ | Partial |
| Background jobs | ❌ (proposed) | N/A | ✅ |
| Interactive tutorials | ❌ (proposed) | ✅ | ✅ |
| PDF reports | ❌ (proposed) | N/A | ✅ |

---

*This document was generated through systematic codebase analysis across code quality, security, observability, documentation, functionality, and architecture dimensions.*
