# Circuit Breaker and Timeout Configuration

This project implements the circuit breaker pattern and request timeouts to improve resilience and prevent cascading failures.

## Features

### Request Timeout Middleware
- **Automatic timeout enforcement** for all API requests
- **Configurable timeout duration** (default: 5 minutes)
- **Slow request logging** for performance monitoring
- **Path exclusion** for WebSocket and streaming endpoints

### Circuit Breaker
- **Automatic failure detection** and circuit opening
- **Configurable thresholds** for failure count and recovery time
- **State management**: CLOSED → OPEN → HALF_OPEN → CLOSED
- **Statistics tracking** for monitoring
- **Decorator-based protection** for sync and async functions

## Configuration

### Environment Variables

```bash
# Timeout configuration
API_TIMEOUT_SECONDS=300  # 5 minutes default

# Circuit breaker configuration
CIRCUIT_BREAKER_ENABLED=true
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5  # Open after 5 failures
CIRCUIT_BREAKER_RECOVERY_TIMEOUT=60  # Wait 60s before testing recovery
```

### Settings in config.py

```python
from config import get_settings

settings = get_settings()

print(f"API Timeout: {settings.api_timeout_seconds}s")
print(f"Circuit Breaker Enabled: {settings.circuit_breaker_enabled}")
```

## Usage

### 1. Request Timeout Middleware

The timeout middleware is automatically applied to all API requests.

**Manual setup** (already configured in server.py):

```python
from fastapi import FastAPI
from analysis_engine.resilience import TimeoutMiddleware

app = FastAPI()

# Add timeout middleware
app.add_middleware(
    TimeoutMiddleware,
    timeout_seconds=300,  # 5 minutes
    exclude_paths=["/ws", "/stream"]  # Exclude WebSocket/streaming
)
```

**Behavior:**
- Requests exceeding timeout return **504 Gateway Timeout**
- Slow requests (>10s) are logged as warnings
- WebSocket and streaming endpoints are excluded

**Example response when timeout occurs:**

```json
{
  "error": "Request timeout",
  "message": "Request exceeded maximum duration of 300 seconds",
  "timeout_seconds": 300,
  "request_id": "req-abc123"
}
```

### 2. Circuit Breaker for External Services

Protect calls to external services (LLM APIs, threat intelligence) from cascading failures.

**Example: Protecting LLM API calls**

```python
from analysis_engine.resilience import get_circuit_breaker

# Get or create circuit breaker for LLM
llm_breaker = get_circuit_breaker(
    name="llm_api",
    failure_threshold=5,  # Open after 5 failures
    recovery_timeout=60,  # Wait 60s before retry
    timeout=30.0  # 30s request timeout
)

@llm_breaker.protect
async def call_llm_api(prompt: str) -> str:
    """Call LLM API with circuit breaker protection."""
    response = await llm_client.complete(prompt)
    return response.text
```

**Example: Protecting threat intelligence lookups**

```python
from analysis_engine.resilience import get_circuit_breaker

threat_intel_breaker = get_circuit_breaker(
    name="threat_intel",
    failure_threshold=3,
    recovery_timeout=120,  # 2 minutes
    timeout=10.0
)

@threat_intel_breaker.protect
async def lookup_ip(ip_address: str) -> dict:
    """Look up IP with circuit breaker protection."""
    return await abuse_ipdb_client.check(ip_address)
```

### 3. Circuit Breaker States

```
CLOSED (Normal)
    │
    ├─ < 5 failures → stays CLOSED
    │
    └─ ≥ 5 failures → OPEN
                        │
                        ├─ Wait 60s → HALF_OPEN
                        │              │
                        │              ├─ 2 successes → CLOSED
                        │              │
                        │              └─ 1 failure → OPEN
                        │
                        └─ Requests rejected with CircuitBreakerError
```

**CLOSED**: Normal operation, failures are counted  
**OPEN**: Circuit is open, all requests are immediately rejected  
**HALF_OPEN**: Testing if service recovered, limited requests allowed

### 4. Monitoring Circuit Breaker Status

```python
from analysis_engine.resilience import get_circuit_breaker

breaker = get_circuit_breaker("llm_api")

# Check state
if breaker.is_open:
    print("LLM API is currently unavailable")

# Get statistics
stats = breaker.get_stats()
print(f"State: {stats.state.value}")
print(f"Failures: {stats.failure_count}")
print(f"Total calls: {stats.total_calls}")
print(f"Rejected: {stats.rejected_calls}")
```

**Add health check endpoint:**

```python
from fastapi import FastAPI
from analysis_engine.resilience import get_all_circuit_breakers

@app.get("/health/circuit-breakers")
async def circuit_breaker_health():
    breakers = get_all_circuit_breakers()
    
    return {
        breaker_name: {
            "state": breaker.get_stats().state.value,
            "failures": breaker.get_stats().failure_count,
            "is_healthy": breaker.is_closed
        }
        for breaker_name, breaker in breakers.items()
    }
```

**Example response:**

```json
{
  "llm_api": {
    "state": "closed",
    "failures": 0,
    "is_healthy": true
  },
  "threat_intel": {
    "state": "open",
    "failures": 5,
    "is_healthy": false
  }
}
```

### 5. Graceful Degradation

When circuit breaker opens, implement fallback logic:

```python
from analysis_engine.resilience import CircuitBreakerError

async def generate_threat_narrative(session_data: dict) -> str:
    """Generate narrative with fallback when LLM unavailable."""
    try:
        # Try LLM-generated narrative
        return await call_llm_api(session_data)
    
    except CircuitBreakerError:
        logger.warning("LLM circuit breaker open, using template fallback")
        # Fallback to template-based narrative
        return generate_template_narrative(session_data)
```

### 6. Manual Circuit Reset

For administrative purposes (e.g., after fixing root cause):

```python
from analysis_engine.resilience import get_circuit_breaker

breaker = get_circuit_breaker("llm_api")
breaker.reset()  # Manually close circuit
```

## Integration Example

**Complete example with both timeout and circuit breaker:**

```python
from fastapi import FastAPI, HTTPException
from analysis_engine.resilience import (
    TimeoutMiddleware,
    get_circuit_breaker,
    CircuitBreakerError
)

app = FastAPI()

# Add timeout middleware
app.add_middleware(
    TimeoutMiddleware,
    timeout_seconds=300
)

# Create circuit breaker
llm_breaker = get_circuit_breaker(
    name="llm_api",
    failure_threshold=5,
    recovery_timeout=60
)

@app.post("/analyze")
async def analyze_telemetry(file: UploadFile):
    """
    Analyze telemetry with timeout and circuit breaker protection.
    
    - Request timeout: 300s (enforced by middleware)
    - LLM calls: Protected by circuit breaker
    """
    # Load and parse (within timeout)
    events = await load_events(file)
    sessions = await correlate_sessions(events)
    
    # Generate narrative with circuit breaker
    try:
        narrative = await generate_llm_narrative(sessions)
    except CircuitBreakerError:
        # Graceful degradation
        narrative = generate_template_narrative(sessions)
    
    return {
        "sessions": sessions,
        "narrative": narrative,
        "llm_available": llm_breaker.is_closed
    }

@llm_breaker.protect
async def generate_llm_narrative(sessions: list) -> str:
    """Generate narrative using LLM (protected by circuit breaker)."""
    response = await openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Analyze: {sessions}"}]
    )
    return response.choices[0].message.content
```

## Best Practices

1. **Set appropriate timeouts**:
   - API requests: 5 minutes (default)
   - LLM calls: 30-60 seconds
   - Database queries: 10-30 seconds
   - Threat intel lookups: 5-10 seconds

2. **Configure failure thresholds based on criticality**:
   - Critical services: Higher threshold (10+)
   - Optional services: Lower threshold (3-5)

3. **Implement fallback logic**:
   - Use templates when LLM unavailable
   - Cache threat intel data
   - Provide partial results

4. **Monitor circuit breaker states**:
   - Add health check endpoints
   - Alert when circuits open
   - Track recovery time

5. **Test failure scenarios**:
   - Simulate service outages
   - Verify graceful degradation
   - Check recovery behavior

## Troubleshooting

### Request Timeouts

**Problem**: Legitimate requests timing out

**Solution**:
- Increase `API_TIMEOUT_SECONDS`
- Optimize slow operations
- Use streaming for large datasets

### Circuit Breaker Opening Frequently

**Problem**: Circuit opens under normal load

**Solution**:
- Increase `CIRCUIT_BREAKER_FAILURE_THRESHOLD`
- Increase timeout for specific operations
- Investigate root cause of failures

### Circuit Breaker Not Opening

**Problem**: Failures not triggering circuit breaker

**Solution**:
- Verify circuit breaker is protecting the function
- Check if exceptions are being caught elsewhere
- Review failure threshold configuration

## Metrics and Monitoring

Track these metrics for production deployments:

- **Timeout rate**: `timeout_requests / total_requests`
- **Circuit breaker state**: gauge (0=closed, 1=open, 0.5=half-open)
- **Circuit open duration**: histogram
- **Rejected requests**: counter
- **Successful recoveries**: counter

Example Prometheus metrics:

```python
from prometheus_client import Counter, Gauge, Histogram

circuit_breaker_state = Gauge(
    'circuit_breaker_state',
    'Circuit breaker state (0=closed, 1=open, 0.5=half_open)',
    ['breaker_name']
)

circuit_breaker_rejected = Counter(
    'circuit_breaker_rejected_total',
    'Total requests rejected by circuit breaker',
    ['breaker_name']
)
```

## Further Reading

- [Netflix Hystrix Circuit Breaker](https://github.com/Netflix/Hystrix/wiki/How-it-Works#CircuitBreaker)
- [Martin Fowler: Circuit Breaker](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Azure: Timeout Pattern](https://learn.microsoft.com/en-us/azure/architecture/patterns/timeout)

