# GitHub Repository Feature Discovery Analysis

## Repository: Secure-AI-Threat-Hunting-Simulator

**Analysis Date**: 2025-12-26
**Repository Version**: v6.0.0
**Analyst**: Claude (Automated Analysis)

---

## Executive Summary

This analysis identifies **8 high-impact feature opportunities** for the Secure-AI-Threat-Hunting-Simulator. The project is a sophisticated threat hunting training platform with strong architecture but opportunities for improvement in test coverage, developer experience, and integration capabilities.

---

## Priority Feature Summary

| # | Feature | Category | Effort | Value | Priority Score |
|---|---------|----------|--------|-------|----------------|
| 1 | Expand Unit Test Coverage | Code Quality | Medium | High | 1.5 |
| 2 | Add OpenAPI Client SDK Generator | Developer Experience | Low | High | 3.0 |
| 3 | Enforce RBAC at API Endpoints | Security | Medium | High | 1.5 |
| 4 | Add Atomic Red Team Integration | Functional Enhancement | Medium | High | 1.5 |
| 5 | Fix Bare Exception Handlers in ML Modules | Code Quality | Low | Medium | 2.0 |
| 6 | Add WebSocket Rate Limiting | Security | Low | Medium | 2.0 |
| 7 | Create Interactive Scenario Builder UI | Functional Enhancement | High | High | 1.0 |
| 8 | Add Distributed Tracing (OpenTelemetry) | Observability | Medium | Medium | 1.0 |

---

## Detailed Feature Requests

---

### Feature #1: Expand Unit Test Coverage

**Category**: Code Quality & Optimization

**Problem Statement**:
The repository has only **25 test functions across 3 test files** (806 lines of tests) covering **109 Python files** (~14,000+ lines of production code). This represents approximately **5% test coverage** by file count. Critical modules like the API server (1,448 lines), ML anomaly detector (16.8 KB), and enterprise features (RBAC, audit logging, compliance) have no dedicated unit tests.

**Proposed Solution**:
- Create `tests/test_api_server.py` with async endpoint testing using `pytest-asyncio` and `httpx.AsyncClient`
- Add `tests/test_ml_anomaly.py` for Isolation Forest model validation
- Add `tests/test_enterprise_rbac.py` for permission enforcement testing
- Add `tests/test_cache.py` for Redis caching layer verification
- Implement integration tests for the full analysis pipeline
- Target **80% code coverage** as measured by pytest-cov

**File Locations to Test**:
- `analysis_engine/api/server.py` - 0% coverage currently
- `analysis_engine/ml/anomaly_detector.py` - 0% coverage
- `analysis_engine/enterprise/rbac.py` - 0% coverage
- `analysis_engine/cache.py` - 0% coverage

**Impact Assessment**:
- **Effort**: Medium (3-4 days)
- **Value**: High
- **Priority Score**: 1.5

**Success Metrics**:
- Code coverage increases from ~5% to 80%+
- CI pipeline pytest step completes with >100 tests passing
- Zero regressions introduced by future PRs due to test failures

---

### Feature #2: Add OpenAPI Client SDK Generator

**Category**: Documentation & Developer Experience

**Problem Statement**:
While the FastAPI server auto-generates OpenAPI documentation at `/docs`, there is no official client SDK for consuming the API. Developers integrating with the platform must manually write HTTP clients, leading to inconsistent implementations and increased onboarding friction.

**Proposed Solution**:
- Add `openapi-generator-cli` to development dependencies
- Create `scripts/generate-sdk.sh` script to generate TypeScript, Python, and Go clients
- Export `openapi.json` schema to `docs/api/openapi.json` in CI pipeline
- Add SDK generation job to `.github/workflows/ci.yml`
- Document SDK installation in README.md

**Implementation**:
```bash
# Add to scripts/generate-sdk.sh
openapi-generator-cli generate \
  -i http://localhost:8000/openapi.json \
  -g typescript-axios \
  -o ./sdk/typescript

openapi-generator-cli generate \
  -i http://localhost:8000/openapi.json \
  -g python \
  -o ./sdk/python
```

**Impact Assessment**:
- **Effort**: Low (1 day)
- **Value**: High
- **Priority Score**: 3.0 ⭐ (Quick Win)

**Success Metrics**:
- SDK packages published to npm/PyPI
- Time-to-first-API-call reduced from hours to minutes
- Zero documentation drift between API and SDK

---

### Feature #3: Enforce RBAC at API Endpoints

**Category**: Security Posture

**Problem Statement**:
The enterprise RBAC system in `analysis_engine/enterprise/rbac.py` defines 28 granular permissions and 9 pre-defined roles, but these are **not enforced at the API endpoint level**. Currently, any authenticated user can access all endpoints regardless of their role. This creates a significant security gap for enterprise deployments.

**Proposed Solution**:
- Create `analysis_engine/api/permissions.py` with FastAPI dependency injection decorators
- Implement `@require_permission(Permission.VIEW_EVENTS)` decorator pattern
- Add role-to-permission mapping middleware
- Update all protected endpoints with appropriate permission requirements
- Add permission check logging to audit trail

**Example Implementation**:
```python
# analysis_engine/api/permissions.py
from functools import wraps
from fastapi import Depends, HTTPException
from analysis_engine.enterprise.rbac import Permission, has_permission

def require_permission(permission: Permission):
    async def permission_checker(user = Depends(get_current_user)):
        if not has_permission(user, permission):
            raise HTTPException(403, f"Missing permission: {permission.value}")
        return user
    return Depends(permission_checker)

# Usage in server.py
@app.post("/analyze/upload")
async def upload_telemetry(
    user = require_permission(Permission.VIEW_EVENTS)
):
    ...
```

**Impact Assessment**:
- **Effort**: Medium (2-3 days)
- **Value**: High
- **Priority Score**: 1.5

**Success Metrics**:
- All 15+ API endpoints have explicit permission requirements
- Unauthorized access attempts return 403 with audit logging
- Penetration test confirms no permission bypass vulnerabilities

---

### Feature #4: Add Atomic Red Team Integration

**Category**: Functional Enhancement

**Problem Statement**:
Compared to industry alternatives like [MITRE Caldera](https://caldera.mitre.org/) and [Atomic Red Team](https://atomicredteam.io/), this simulator lacks integration with established ATT&CK test libraries. Atomic Red Team provides 1,225+ atomic tests covering 261 ATT&CK techniques. Integration would significantly expand the platform's attack coverage and credibility.

**Proposed Solution**:
- Add `atomics/` directory with git submodule linking to `redcanaryco/atomic-red-team`
- Create `generator/atomic_importer.py` to parse Atomic YAML files
- Map Atomic tests to existing telemetry synthesis patterns
- Add API endpoint `POST /scenarios/import-atomic` for dynamic imports
- Create documentation for atomic test execution

**Implementation Steps**:
1. `git submodule add https://github.com/redcanaryco/atomic-red-team atomics/`
2. Parse `atomics/T*/T*.yaml` files for attack metadata
3. Generate synthetic CloudTrail-like logs based on atomic test descriptions
4. Map to MITRE ATT&CK technique IDs already supported

**Impact Assessment**:
- **Effort**: Medium (3-4 days)
- **Value**: High
- **Priority Score**: 1.5

**Success Metrics**:
- 100+ Atomic Red Team tests importable via API
- Coverage of 50+ additional ATT&CK techniques
- Integration documented in `docs/atomic_integration.md`

---

### Feature #5: Fix Bare Exception Handlers in ML Modules

**Category**: Code Quality & Optimization

**Problem Statement**:
The ML modules contain **7 bare `except:` clauses** that silently swallow all exceptions, making debugging extremely difficult and potentially hiding critical errors:

- `analysis_engine/ml/behavioral_baseline.py` (3 instances)
- `analysis_engine/ml/anomaly_detector.py` (3 instances)
- `analysis_engine/core/graph_correlation.py` (1 instance)

**Proposed Solution**:
- Replace `except:` with `except Exception as e:` with proper logging
- Add specific exception types where appropriate (ValueError, KeyError, etc.)
- Implement graceful degradation with meaningful error messages
- Add error telemetry to Prometheus metrics

**Example Fix**:
```python
# Before (behavioral_baseline.py)
try:
    result = complex_operation()
except:
    pass  # BAD: Silent failure

# After
try:
    result = complex_operation()
except ValueError as e:
    logger.warning(f"Invalid value in baseline calculation: {e}")
    result = default_value
except Exception as e:
    logger.error(f"Unexpected error in baseline: {e}", exc_info=True)
    raise
```

**Impact Assessment**:
- **Effort**: Low (0.5 days)
- **Value**: Medium
- **Priority Score**: 2.0 ⭐ (Quick Win)

**Success Metrics**:
- Zero bare `except:` clauses in codebase
- Bandit security scan passes with no B110 warnings
- ML errors appear in structured logs with full context

---

### Feature #6: Add WebSocket Rate Limiting

**Category**: Security Posture

**Problem Statement**:
The HTTP API endpoints have proper rate limiting via `slowapi` (10-30 requests/minute per endpoint), but **WebSocket endpoints have no rate limiting**. This creates a denial-of-service vector where malicious clients can flood the server with WebSocket messages.

Affected endpoints:
- `/ws/scenario/{scenario_name}` (line 724)
- `/ws/analysis` (line 772)
- `/ws/live` (line 827)

**Proposed Solution**:
- Implement token bucket rate limiter in `analysis_engine/api/websocket.py`
- Add per-connection message rate limiting (e.g., 100 messages/second)
- Add connection count limit per IP address
- Implement automatic disconnection for rate-limited clients
- Log rate limit violations to audit trail

**Example Implementation**:
```python
class WebSocketRateLimiter:
    def __init__(self, max_messages: int = 100, window_seconds: int = 1):
        self.limits: Dict[str, List[float]] = {}

    async def check_limit(self, client_id: str) -> bool:
        now = time.time()
        if client_id not in self.limits:
            self.limits[client_id] = []

        # Remove old timestamps
        self.limits[client_id] = [
            t for t in self.limits[client_id]
            if now - t < self.window_seconds
        ]

        if len(self.limits[client_id]) >= self.max_messages:
            return False

        self.limits[client_id].append(now)
        return True
```

**Impact Assessment**:
- **Effort**: Low (1 day)
- **Value**: Medium
- **Priority Score**: 2.0 ⭐ (Quick Win)

**Success Metrics**:
- WebSocket flood attacks blocked automatically
- Rate-limited connections logged with client IP
- System remains responsive under malicious load

---

### Feature #7: Create Interactive Scenario Builder UI

**Category**: Functional Enhancement

**Problem Statement**:
Currently, creating custom attack scenarios requires writing Python code in `generator/attack_traces/`. There is no graphical interface for non-developers to design attack sequences, limiting the platform's accessibility for security analysts and SOC teams who may not have Python expertise.

**Proposed Solution**:
- Add `ui/soc_dashboard/src/components/ScenarioBuilder.tsx` component
- Implement drag-and-drop ATT&CK technique selection
- Create visual timeline editor for attack phases
- Add JSON export/import for scenario definitions
- Integrate with existing `/scenarios` API endpoints
- Add preview mode showing generated telemetry samples

**UI Components**:
1. **Technique Selector**: Searchable MITRE ATT&CK technique picker
2. **Timeline Editor**: Visual representation of attack progression
3. **Parameter Panel**: Configure duration, noise ratio, target resources
4. **Telemetry Preview**: Real-time preview of generated events
5. **Export Options**: Save as YAML, JSON, or Python code

**Impact Assessment**:
- **Effort**: High (5+ days)
- **Value**: High
- **Priority Score**: 1.0

**Success Metrics**:
- Non-developers can create custom scenarios in <10 minutes
- 50% reduction in scenario creation support tickets
- User-created scenarios shareable via JSON export

---

### Feature #8: Add Distributed Tracing (OpenTelemetry)

**Category**: Observability Stack

**Problem Statement**:
The platform has excellent logging and Prometheus metrics, but lacks **distributed tracing** capability. For complex analysis pipelines that span multiple components (API → Pipeline → ML → Database → Cache), it's difficult to trace the full request lifecycle and identify bottlenecks.

**Proposed Solution**:
- Add `opentelemetry-api` and `opentelemetry-sdk` to requirements.txt
- Integrate OpenTelemetry instrumentation in `analysis_engine/pipeline.py`
- Add trace context propagation across async boundaries
- Configure Jaeger/Zipkin exporter in `config.py`
- Instrument database, cache, and LLM calls

**Implementation**:
```python
# Add to pipeline.py
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor

tracer = trace.get_tracer("threat-hunting-simulator")

class ThreatHuntingPipeline:
    def analyze_telemetry_file(self, file_path: str):
        with tracer.start_as_current_span("analyze_telemetry"):
            with tracer.start_as_current_span("load_events"):
                events = self.loader.load(file_path)
            with tracer.start_as_current_span("correlate_sessions"):
                sessions = self.correlator.correlate(events)
            # ... etc
```

**Impact Assessment**:
- **Effort**: Medium (2-3 days)
- **Value**: Medium
- **Priority Score**: 1.0

**Success Metrics**:
- End-to-end request traces visible in Jaeger UI
- P95 latency bottlenecks identifiable within 5 minutes
- Zero blind spots in analysis pipeline debugging

---

## Additional Recommendations

### Quick Fixes (< 1 hour each)

1. **Update frontend dependencies**: `react-scripts` 5.0.1 → 5.0.2, check for security patches
2. **Add `.nvmrc` file**: Pin Node.js version to 18 LTS for consistency
3. **Enable TypeScript strict mode**: Add `"strict": true` to `ui/soc_dashboard/tsconfig.json`
4. **Extract hardcoded limits**: Move `max_events = 10000`, `max_rules = 50` to `config.py`

### Future Considerations (Beyond Scope)

1. **Terraform Integration**: Generate cloud topologies from Terraform state files
2. **Scenario Replay/Diff**: Compare analysis results across scenario versions
3. **Multi-Language Detection Rules**: Extend beyond Sigma to Splunk SPL, Elastic EQL
4. **Federated Learning**: Train ML models across tenant boundaries without sharing data

---

## Competitive Analysis Summary

Compared to leading alternatives:

| Feature | This Project | Atomic Red Team | MITRE Caldera |
|---------|-------------|-----------------|---------------|
| ATT&CK Coverage | 70+ techniques | 261 techniques | 527 procedures |
| Agent-based | No | No | Yes |
| Cloud-native | ✅ Strong | ⚠️ Limited | ⚠️ Limited |
| ML Detection | ✅ Strong | ❌ None | ⚠️ Limited |
| Custom Scenarios | ✅ Code-based | ✅ YAML-based | ✅ GUI-based |
| SIEM Integration | ✅ 5 platforms | ❌ None | ⚠️ Limited |

**Sources**:
- [Comparing Red Team Platforms (Red Canary)](https://redcanary.com/blog/testing-and-validation/atomic-red-team/comparing-red-team-platforms/)
- [Open Source Adversary Emulation Tools (Picus Security)](https://www.picussecurity.com/resource/blog/data-driven-comparison-between-open-source-adversary-emulation-tools)

---

## Implementation Roadmap

### Phase 1: Quick Wins (Week 1)
- Feature #2: OpenAPI SDK Generator
- Feature #5: Fix Bare Exception Handlers
- Feature #6: WebSocket Rate Limiting

### Phase 2: Core Improvements (Week 2-3)
- Feature #1: Expand Test Coverage
- Feature #3: Enforce RBAC at Endpoints

### Phase 3: Advanced Features (Week 4+)
- Feature #4: Atomic Red Team Integration
- Feature #8: OpenTelemetry Tracing
- Feature #7: Interactive Scenario Builder

---

*Report generated by automated codebase analysis. Review with domain experts before implementation.*
