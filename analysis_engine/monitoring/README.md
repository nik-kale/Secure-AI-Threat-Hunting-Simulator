# Performance Monitoring System

Comprehensive performance monitoring and observability for the AI Threat Hunting Simulator.

## Overview

This monitoring system provides:

- **Prometheus Metrics**: Production-ready metrics for monitoring and alerting
- **Performance Profiling**: Detailed timing and memory analysis
- **Structured Logging**: JSON-formatted logs with correlation IDs and performance metrics
- **Grafana Dashboard**: Pre-built visualization dashboard

## Components

### 1. Metrics (`metrics.py`)

Prometheus-compatible metrics for tracking system performance.

#### Available Metrics

**Analysis Metrics:**
- `analysis_requests_total`: Counter for total analysis requests (labels: scenario, status)
- `analysis_duration_seconds`: Histogram of analysis durations (labels: scenario)
- `current_analysis_jobs`: Gauge for active analysis jobs

**Event Processing:**
- `events_processed_total`: Counter for processed events (labels: event_source)
- `events_processing_errors_total`: Counter for processing errors (labels: error_type)

**Session Detection:**
- `sessions_detected_total`: Counter for detected sessions (labels: is_malicious)
- `sessions_analysis_duration_seconds`: Histogram of session analysis durations

**LLM Metrics:**
- `llm_requests_total`: Counter for LLM requests (labels: agent, model, status)
- `llm_request_duration_seconds`: Histogram of LLM request durations (labels: agent, model)
- `llm_tokens_used_total`: Counter for token usage (labels: agent, model, token_type)

**Database Metrics:**
- `database_queries_total`: Counter for database queries (labels: operation, table, status)
- `database_query_duration_seconds`: Histogram of query durations (labels: operation, table)

**HTTP Metrics:**
- `http_requests_total`: Counter for HTTP requests (labels: method, endpoint, status_code)
- `http_request_duration_seconds`: Histogram of request durations (labels: method, endpoint)

**Resource Metrics:**
- `memory_usage_bytes`: Gauge for memory usage (labels: type)
- `file_upload_size_bytes`: Histogram of uploaded file sizes

**Health & Errors:**
- `health_check_status`: Gauge for health status (labels: component)
- `errors_total`: Counter for errors (labels: error_type, component)
- `iocs_extracted_total`: Counter for extracted IOCs (labels: ioc_type)

#### Usage Examples

```python
from analysis_engine.monitoring import track_analysis, record_event_processed

# Decorator for automatic tracking
@track_analysis(scenario="apt_simulation")
def analyze_telemetry(data):
    # Your analysis logic
    pass

# Manual metric recording
record_event_processed("upload", 1000)
record_file_upload(5242880)  # 5MB
record_ioc_extracted("ip", 5)
```

### 2. Profiler (`profiler.py`)

Detailed performance profiling with timing and memory tracking.

#### Usage Examples

**As a Context Manager:**

```python
from analysis_engine.monitoring import Profiler

with Profiler("data_processing", track_memory=True) as profiler:
    # Add metadata
    profiler.add_metadata("dataset_size", len(data))

    # Time specific operations
    with profiler.time("load_data"):
        data = load_dataset()

    with profiler.time("process_data"):
        results = process_dataset(data)

    # Take memory snapshots
    profiler.snapshot_memory("after_processing")

    # Save report
    profiler.save_report(Path("reports/profile.json"))

    # Print summary
    profiler.print_summary()
```

**As a Decorator:**

```python
from analysis_engine.monitoring import profile

@profile(name="heavy_computation", save_report=True)
def process_large_dataset(data):
    # Processing logic
    return results
```

**Simple Timing:**

```python
from analysis_engine.monitoring import timed

@timed
def slow_operation():
    # This will automatically log execution time
    time.sleep(1)
```

### 3. Structured Logging (`logger.py`)

JSON-formatted logging with correlation tracking and performance metrics.

#### Usage Examples

**Basic Logging:**

```python
from analysis_engine.monitoring import analysis_logger

# Simple logging with structured fields
analysis_logger.info(
    "Processing telemetry",
    event_count=1000,
    source="upload"
)

# Performance logging
analysis_logger.performance(
    "Analysis completed",
    duration=3.14,
    operation="threat_hunting",
    events_processed=1000
)

# Request logging
analysis_logger.request(
    "API request completed",
    method="POST",
    path="/analyze/upload",
    status_code=200,
    duration=2.5
)
```

**Correlation IDs:**

```python
from analysis_engine.monitoring import with_correlation_id, api_logger

@with_correlation_id
def handle_request(data):
    # All logs within this function will have the same correlation_id
    api_logger.info("Request started", request_size=len(data))
    process_data(data)
    api_logger.info("Request completed")
```

**Request Context:**

```python
from analysis_engine.monitoring import RequestContext

with RequestContext("telemetry_analysis", event_count=1000):
    # Automatically logs start/end with timing
    # Manages correlation IDs
    results = analyze_telemetry(data)
```

**Decorators:**

```python
from analysis_engine.monitoring import log_performance, log_function_call

@log_performance(operation="data_analysis")
def analyze_data(data):
    # Automatically logs performance metrics
    return results

@log_function_call(log_args=True, log_result=True)
def process_event(event_id, event_data):
    # Logs function calls with arguments and results
    return processed_data
```

## API Endpoints

### GET /metrics

Returns Prometheus-formatted metrics for scraping.

```bash
curl http://localhost:8000/metrics
```

**Response:** Prometheus text format
```
# HELP analysis_requests_total Total number of analysis requests
# TYPE analysis_requests_total counter
analysis_requests_total{scenario="apt_simulation",status="success"} 42.0
...
```

### GET /stats

Returns JSON-formatted statistics for dashboards.

```bash
curl http://localhost:8000/stats
```

**Response:**
```json
{
  "timestamp": 1699999999.123,
  "version": "3.0.0",
  "metrics": { ... },
  "summary": {
    "analysis": {
      "total_requests": 100,
      "success_requests": 95,
      "failed_requests": 5,
      "success_rate": 95.0
    },
    "events": {
      "total_processed": 50000
    },
    "sessions": {
      "total_detected": 42,
      "malicious_detected": 8,
      "malicious_rate": 19.05
    }
  }
}
```

### GET /health

Enhanced health check with component status.

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "3.0.0",
  "timestamp": 1699999999.123,
  "components": {
    "pipeline": {
      "status": "healthy",
      "check_duration": 0.001
    },
    "system": {
      "status": "healthy",
      "memory_percent": 45.2,
      "disk_percent": 60.1,
      "check_duration": 0.002
    }
  }
}
```

## Grafana Dashboard

### Installation

1. Import the dashboard:
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d @grafana_dashboard.json \
  http://admin:admin@localhost:3000/api/dashboards/db
```

2. Or manually import via Grafana UI:
   - Go to Dashboards → Import
   - Upload `grafana_dashboard.json`

### Dashboard Features

The dashboard includes 20 panels organized into sections:

**Overview (Row 1):**
- Total Analysis Requests
- Success Rate
- Current Analysis Jobs
- Total Events Processed

**Performance (Rows 2-3):**
- Analysis Request Rate (by scenario and status)
- Analysis Duration (p50, p95, p99 percentiles)
- Event Processing Rate
- Sessions Detected (malicious vs benign)

**Resources (Row 4):**
- Memory Usage (RSS, VMS, System)
- HTTP Request Rate
- HTTP Request Duration

**AI/LLM (Row 5):**
- LLM Request Rate (by agent)
- LLM Token Usage (prompt vs completion)

**Database (Row 6):**
- Database Query Rate
- Database Query Duration

**IOCs & Errors (Row 7):**
- IOCs Extracted (by type)
- Error Rate (with alerting)

**Health (Row 8):**
- Component Health Status
- File Upload Statistics

### Alerts

The dashboard includes a pre-configured alert for high error rates:
- **Trigger:** Error rate > 0.1 errors/sec for 5 minutes
- **Action:** Notification (configure in Grafana)

## Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'threat-hunting-api'
    scrape_interval: 10s
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
```

## Docker Compose Example

```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - API_KEY=your-api-key

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana_dashboard.json:/etc/grafana/provisioning/dashboards/threat-hunting.json
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_INSTALL_PLUGINS=grafana-piechart-panel

volumes:
  prometheus_data:
  grafana_data:
```

## File Logging

Enable file-based logging with rotation:

```python
from pathlib import Path
from analysis_engine.monitoring import setup_file_logging

# Setup rotating file logs (10MB per file, 5 backups)
setup_file_logging(
    log_dir=Path("/var/log/threat-hunting"),
    log_file="analysis.log",
    max_bytes=10 * 1024 * 1024,
    backup_count=5
)
```

## Best Practices

### 1. Use Decorators for Automatic Tracking

```python
from analysis_engine.monitoring import track_analysis, log_performance

@track_analysis(scenario="ransomware_detection")
@log_performance()
def analyze_ransomware_indicators(data):
    return results
```

### 2. Add Correlation IDs for Request Tracking

```python
from analysis_engine.monitoring import RequestContext

with RequestContext("batch_analysis", batch_size=100):
    for item in batch:
        process_item(item)  # All logs will share correlation_id
```

### 3. Profile Performance-Critical Code

```python
from analysis_engine.monitoring import Profiler

with Profiler("critical_path", track_memory=True) as p:
    with p.time("parsing"):
        events = parse_events(data)

    with p.time("correlation"):
        sessions = correlate_events(events)

    p.snapshot_memory("after_correlation")
    p.save_report(Path("profiles/critical_path.json"))
```

### 4. Record Business Metrics

```python
from analysis_engine.monitoring import (
    record_event_processed,
    record_ioc_extracted
)

# Record events processed
record_event_processed("sysmon", len(events))

# Record IOCs found
for ioc_type, iocs in extracted_iocs.items():
    record_ioc_extracted(ioc_type, len(iocs))
```

### 5. Monitor Health Proactively

```python
from analysis_engine.monitoring import record_health_check

def check_database_health():
    start = time.time()
    try:
        db.ping()
        healthy = True
    except:
        healthy = False

    record_health_check(
        "database",
        healthy,
        time.time() - start
    )
```

## Troubleshooting

### High Memory Usage

1. Check memory metrics in Grafana
2. Review profiling reports for memory leaks
3. Enable memory tracking:
```python
from analysis_engine.monitoring import collect_system_metrics
collect_system_metrics()  # Updates memory gauges
```

### Slow Performance

1. Check duration histograms (p95, p99)
2. Profile slow operations:
```python
@profile(save_report=True, report_dir=Path("performance"))
def slow_function():
    pass
```
3. Review logs for performance metrics:
```bash
cat analysis.log | grep '"performance"' | jq '.performance.duration_seconds'
```

### Missing Metrics

1. Verify Prometheus is scraping: `http://localhost:9090/targets`
2. Check metrics endpoint: `curl http://localhost:8000/metrics`
3. Verify decorator usage on functions

## Performance Impact

The monitoring system is designed for production use:

- **Metrics**: ~0.1ms overhead per metric recording
- **Logging**: JSON serialization adds ~0.5ms per log entry
- **Profiling**: ~1-5% overhead when enabled (use sparingly in production)

For production, consider:
- Disabling memory tracking in profiler
- Using sampling for trace-level logs
- Setting appropriate Prometheus scrape intervals (10-30s)

## License

Part of the AI Threat Hunting Simulator project.
