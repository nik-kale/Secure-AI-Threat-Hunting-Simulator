# OpenTelemetry Distributed Tracing

This project integrates OpenTelemetry for distributed tracing, enabling you to trace requests across the entire analysis pipeline.

## Features

- **Automatic instrumentation** for FastAPI, HTTPX, Redis, and SQLAlchemy
- **Multiple exporters**: Console, Jaeger, OTLP (gRPC/HTTP)
- **Custom span creation** for pipeline stages
- **Trace context propagation** across async operations
- **Production-ready configuration** with environment variables

## Quick Start

### 1. Enable Tracing

Set environment variables in your `.env` file:

```bash
# Enable OpenTelemetry tracing
OTEL_ENABLED=true

# Service information
OTEL_SERVICE_NAME=threat-hunting-simulator
OTEL_SERVICE_VERSION=3.0.0

# Exporter configuration (choose one)
OTEL_EXPORTER_TYPE=console  # For development (prints to console)
# OTEL_EXPORTER_TYPE=jaeger  # For Jaeger
# OTEL_EXPORTER_TYPE=otlp_grpc  # For OTLP gRPC (e.g., Tempo, Honeycomb)
# OTEL_EXPORTER_TYPE=otlp_http  # For OTLP HTTP

# Exporter endpoint (if using Jaeger or OTLP)
# OTEL_EXPORTER_ENDPOINT=http://localhost:4317  # OTLP gRPC
# JAEGER_AGENT_HOST=localhost
# JAEGER_AGENT_PORT=6831

# Optional: Also export to console for debugging
OTEL_CONSOLE_EXPORTER=false

# Environment
ENVIRONMENT=development
```

### 2. Initialize in Your Application

The tracing is automatically initialized when the API server starts if `OTEL_ENABLED=true`.

For manual initialization:

```python
from analysis_engine.monitoring import init_tracing

# Initialize tracing
tracing_manager = init_tracing(
    service_name="threat-hunting-simulator",
    service_version="3.0.0",
    exporter_type="jaeger",
    exporter_endpoint="http://localhost:4317"
)

# Instrument FastAPI (done automatically in server.py)
from fastapi import FastAPI
app = FastAPI()
tracing_manager.instrument_fastapi(app)
```

## Using Tracing

### Automatic Instrumentation

The following components are automatically instrumented:

- **FastAPI endpoints**: All HTTP requests are traced
- **HTTPX client**: Outgoing HTTP requests (e.g., to LLM APIs)
- **Redis**: Cache operations
- **SQLAlchemy**: Database queries

### Custom Spans

Add custom spans to trace specific operations:

```python
from analysis_engine.monitoring import get_tracing_manager

tracing_manager = get_tracing_manager()

# Trace a custom operation
with tracing_manager.trace_operation(
    "load_telemetry",
    attributes={"file": "events.jsonl", "size_mb": 25}
):
    events = load_events_from_file("events.jsonl")
```

### Pipeline Tracing Example

```python
from analysis_engine.monitoring import get_tracer
from opentelemetry import trace

tracer = get_tracer()

def analyze_telemetry(file_path: str):
    with tracer.start_as_current_span("analyze_telemetry") as span:
        span.set_attribute("file.path", file_path)
        
        # Stage 1: Load
        with tracer.start_as_current_span("load_events"):
            events = loader.load(file_path)
            span.set_attribute("events.count", len(events))
        
        # Stage 2: Parse
        with tracer.start_as_current_span("parse_events"):
            parsed = parser.parse(events)
        
        # Stage 3: Correlate
        with tracer.start_as_current_span("correlate_sessions"):
            sessions = correlator.correlate(parsed)
            span.set_attribute("sessions.count", len(sessions))
        
        # Stage 4: MITRE mapping
        with tracer.start_as_current_span("map_mitre_techniques"):
            mitre_mapped = mitre_mapper.map(sessions)
        
        return mitre_mapped
```

### Adding Span Attributes

```python
from analysis_engine.monitoring import get_tracing_manager

tracing_manager = get_tracing_manager()

# Add attributes to current span
tracing_manager.add_span_attributes(
    user_id="user-123",
    request_size_bytes=1024,
    cache_hit=True
)
```

## Viewing Traces

### Using Jaeger (Local Development)

1. Start Jaeger:

```bash
docker run -d --name jaeger \
  -e COLLECTOR_ZIPKIN_HOST_PORT=:9411 \
  -p 5775:5775/udp \
  -p 6831:6831/udp \
  -p 6832:6832/udp \
  -p 5778:5778 \
  -p 16686:16686 \
  -p 14268:14268 \
  -p 14250:14250 \
  -p 9411:9411 \
  jaegertracing/all-in-one:latest
```

2. Configure tracing:

```bash
OTEL_ENABLED=true
OTEL_EXPORTER_TYPE=jaeger
JAEGER_AGENT_HOST=localhost
JAEGER_AGENT_PORT=6831
```

3. View traces at http://localhost:16686

### Using Grafana Tempo

```bash
OTEL_ENABLED=true
OTEL_EXPORTER_TYPE=otlp_grpc
OTEL_EXPORTER_ENDPOINT=http://tempo:4317
```

### Using Honeycomb

```bash
OTEL_ENABLED=true
OTEL_EXPORTER_TYPE=otlp_http
OTEL_EXPORTER_ENDPOINT=https://api.honeycomb.io
# Add authentication headers via environment
```

## Trace Visualization Example

A typical analysis request trace will show:

```
analyze_file (200ms)
├─ load_events (50ms)
├─ parse_events (30ms)
├─ correlate_sessions (80ms)
│  ├─ build_session_graph (40ms)
│  └─ detect_attack_patterns (40ms)
├─ map_mitre_techniques (20ms)
└─ generate_narrative (20ms)
   └─ llm_request (15ms)
      └─ httpx.post (12ms)
```

## Performance Impact

OpenTelemetry adds minimal overhead:

- **Sampling**: Configure sampling rate to reduce volume (default: all traces)
- **Batch processing**: Spans are batched before export
- **Async export**: Exporters run asynchronously

For production, consider:

```bash
# Sample 10% of traces
OTEL_TRACES_SAMPLER=parentbased_traceidratio
OTEL_TRACES_SAMPLER_ARG=0.1
```

## Integration with Existing Monitoring

Traces complement existing monitoring:

- **Metrics (Prometheus)**: What is slow? How many errors?
- **Logs (Structured JSON)**: What happened?
- **Traces (OpenTelemetry)**: Why is it slow? Where did it fail?

Correlation IDs from structured logging are automatically included in traces.

## Troubleshooting

### Traces Not Appearing

1. Check if tracing is enabled: `OTEL_ENABLED=true`
2. Verify exporter configuration
3. Check logs for initialization messages
4. Ensure exporter endpoint is reachable

### High Memory Usage

- Enable sampling for high-volume production
- Reduce span attributes
- Use batch processor (already configured)

### Missing Spans

- Ensure tracer is initialized before operations
- Check for exceptions during span creation
- Verify instrumentation is active

## Docker Compose Example

```yaml
version: '3.8'

services:
  threat-hunting-api:
    build: .
    environment:
      - OTEL_ENABLED=true
      - OTEL_EXPORTER_TYPE=otlp_grpc
      - OTEL_EXPORTER_ENDPOINT=http://tempo:4317
    depends_on:
      - tempo

  tempo:
    image: grafana/tempo:latest
    command: ["-config.file=/etc/tempo.yaml"]
    ports:
      - "3200:3200"   # tempo
      - "4317:4317"   # otlp grpc
      - "4318:4318"   # otlp http
    volumes:
      - ./tempo.yaml:/etc/tempo.yaml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
    volumes:
      - ./grafana-datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml
```

## Best Practices

1. **Name spans meaningfully**: Use operation names like `load_events`, not `function_1`
2. **Add relevant attributes**: Include IDs, counts, sizes, status
3. **Keep span count reasonable**: Don't create spans for every loop iteration
4. **Use sampling in production**: Reduce volume while maintaining visibility
5. **Propagate context**: Ensure trace context flows through async operations

## Further Reading

- [OpenTelemetry Python Docs](https://opentelemetry-python.readthedocs.io/)
- [OTLP Specification](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/otlp.md)
- [Jaeger Documentation](https://www.jaegertracing.io/docs/)
- [Grafana Tempo Documentation](https://grafana.com/docs/tempo/latest/)

