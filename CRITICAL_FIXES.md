# CRITICAL FIXES - APPLY BEFORE DEPLOYMENT

This document contains **must-fix** issues identified in code review. Apply these immediately before any production or public deployment.

---

## 🔴 SECURITY ISSUES (Fix Immediately)

### 1. CORS Vulnerability
**File**: `analysis_engine/api/server.py:24-30`
**Risk**: Allows any origin to access API with credentials

**Current Code**:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ❌ SECURITY RISK
    allow_credentials=True,
)
```

**Fix**:
```python
import os

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
```

**Update `.env.example`**:
```bash
# Add this line
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
```

---

### 2. No API Authentication
**File**: `analysis_engine/api/server.py`
**Risk**: Anyone can upload files and trigger resource-intensive analysis

**Add Security Module** - Create `analysis_engine/api/auth.py`:
```python
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
import os

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Verify API key if configured."""
    expected_key = os.getenv("API_KEY")

    # If no API key set, allow access (development mode)
    if not expected_key:
        return None

    if not api_key or api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key
```

**Update Server**:
```python
# In analysis_engine/api/server.py
from .auth import verify_api_key
from fastapi import Depends

@app.post("/analyze/upload", dependencies=[Depends(verify_api_key)])
async def analyze_upload(file: UploadFile = File(...)):
    # ... existing code
```

**Update `.env.example`**:
```bash
# Add this line (generate with: python -c "import secrets; print(secrets.token_urlsafe(32))")
API_KEY=your-secret-api-key-here
```

---

### 3. File Descriptor Leak
**File**: `analysis_engine/api/server.py:53-78`
**Risk**: Temp files not deleted on exception, can fill disk

**Fix**:
```python
@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)) -> Dict[str, Any]:
    tmp_path = None
    try:
        # Save uploaded file
        with tempfile.NamedTemporaryFile(
            mode='wb',
            suffix=Path(file.filename).suffix,
            delete=False
        ) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = Path(tmp_file.name)

        # Analyze
        results = pipeline.analyze_telemetry_file(tmp_path)
        return results

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        # Always cleanup temp file
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()
```

---

### 4. Docker Security
**File**: `analysis_engine/Dockerfile`
**Risk**: Runs as root user

**Fix**:
```dockerfile
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser generator/ ./generator/
COPY --chown=appuser:appuser analysis_engine/ ./analysis_engine/

# Create output directory with proper permissions
RUN mkdir -p /app/output && chown -R appuser:appuser /app/output

# Switch to non-root user
USER appuser

# Expose API port
EXPOSE 8000

# Run API server
CMD ["python", "-m", "uvicorn", "analysis_engine.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 🟡 CRITICAL BUGS (Fix Before Use)

### 5. Python Version Incompatibility
**File**: `analysis_engine/core/kill_chain.py:98`
**Issue**: Uses Python 3.10+ syntax without version constraint

**Fix**:
```python
# Change line 98 from:
def map_event(self, event: NormalizedEvent) -> KillChainStage | None:

# To:
from typing import Optional
def map_event(self, event: NormalizedEvent) -> Optional[KillChainStage]:
```

---

### 6. Missing Package Files
**Directories**: All `generator/attack_traces/*/` subdirectories
**Issue**: Missing `__init__.py` causes import errors

**Fix**: Create these files:

**`generator/attack_traces/__init__.py`**:
```python
"""Attack trace generators."""
```

**`generator/attack_traces/iam_priv_escalation/__init__.py`**:
```python
"""IAM privilege escalation scenario."""
from .generator import generate_iam_privilege_escalation_scenario

__all__ = ["generate_iam_privilege_escalation_scenario"]
```

**`generator/attack_traces/container_escape/__init__.py`**:
```python
"""Container escape scenario."""
from .generator import generate_container_escape_scenario

__all__ = ["generate_container_escape_scenario"]
```

**`generator/attack_traces/cred_stuffing/__init__.py`**:
```python
"""Credential stuffing scenario."""
from .generator import generate_credential_stuffing_scenario

__all__ = ["generate_credential_stuffing_scenario"]
```

---

### 7. Timestamp Distribution Bug
**File**: `generator/telemetry_synthesizer.py:310-350`
**Issue**: Noise events incorrectly reuse attack event timestamps

**Fix - Replace entire `add_benign_noise` method**:
```python
def add_benign_noise(
    self,
    events: List[Dict[str, Any]],
    noise_ratio: float = 0.3
) -> List[Dict[str, Any]]:
    """
    Add benign background events to make telemetry realistic.

    Args:
        events: List of attack events
        noise_ratio: Ratio of noise events to attack events

    Returns:
        Combined list of events
    """
    num_noise_events = int(len(events) * noise_ratio)

    if not events:
        return events

    # Extract time range from attack events
    timestamps = [self._parse_timestamp(e["timestamp"]) for e in events]
    start_time = min(timestamps)
    end_time = max(timestamps)
    duration_seconds = (end_time - start_time).total_seconds()

    if duration_seconds == 0:
        duration_seconds = 3600  # Default to 1 hour if all events at same time

    noise_events = []

    benign_principals = [
        "arn:aws:iam::123456789012:user/legitimate-user",
        "arn:aws:iam::123456789012:role/AutomationRole",
        "arn:aws:iam::123456789012:role/MonitoringRole",
    ]

    for _ in range(num_noise_events):
        # Generate random timestamp within the attack timeframe
        random_offset = random.uniform(0, duration_seconds)
        timestamp = generate_timestamp(start_time, random_offset)

        event_type = random.choice(["iam", "s3", "api", "network"])

        if event_type == "iam":
            noise_events.append(
                self.create_iam_event(
                    action="GetUser",
                    principal=random.choice(benign_principals),
                    timestamp=timestamp,
                    status="success",
                )
            )
        elif event_type == "s3":
            noise_events.append(
                self.create_s3_event(
                    action="GetObject",
                    principal=random.choice(benign_principals),
                    bucket="public-assets-bucket",
                    key="images/logo.png",
                    timestamp=timestamp,
                )
            )
        elif event_type == "api":
            noise_events.append(
                self.create_api_gateway_event(
                    method="GET",
                    path="/health",
                    timestamp=timestamp,
                    status_code=200,
                )
            )
        elif event_type == "network":
            noise_events.append(
                self.create_network_flow_event(
                    src_ip=generate_ip_address(private=True),
                    dst_ip=generate_ip_address(private=True),
                    src_port=random.randint(10000, 65000),
                    dst_port=443,
                    protocol="TCP",
                    timestamp=timestamp,
                )
            )

    # Combine and sort by timestamp
    all_events = events + noise_events
    all_events.sort(key=lambda e: e["timestamp"])

    return all_events

def _parse_timestamp(self, timestamp_str: str) -> datetime:
    """Parse ISO 8601 timestamp string to datetime."""
    from datetime import datetime
    return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
```

---

### 8. Pipeline Only Saves First Session
**File**: `analysis_engine/pipeline.py:120`
**Issue**: Only first suspicious session saved to reports

**Fix**:
```python
def analyze_telemetry_file(
    self,
    telemetry_path: Path,
    output_dir: Optional[Path] = None
) -> Dict[str, Any]:
    # ... existing code until line 118 ...

    # Generate summary report
    summary = {
        "total_events": len(normalized_events),
        "total_sessions": len(sessions),
        "suspicious_sessions": len(suspicious_sessions),
        "sessions": analysis_results,
    }

    # Write reports if output directory specified
    if output_dir and analysis_results:
        # Save comprehensive report with all sessions
        self.write_reports(summary, output_dir)

        # Optionally save individual session reports
        for idx, session_analysis in enumerate(analysis_results):
            session_dir = output_dir / f"session_{idx+1}"
            session_dir.mkdir(exist_ok=True)
            self.write_reports(session_analysis, session_dir)

    logger.info("Analysis complete")
    return summary
```

---

### 9. Docker Volume Not Used
**File**: `docker-compose.yml:53-54`
**Issue**: Declared volume never mounted

**Fix - Remove or use the volume**:

**Option 1: Remove (simpler)**:
```yaml
# Delete lines 53-54
# volumes:
#   output-data:
```

**Option 2: Use the volume**:
```yaml
services:
  analysis-engine:
    # ... existing config ...
    volumes:
      - output-data:/app/output  # Add this line
      - ./generator:/app/generator
      - ./analysis_engine:/app/analysis_engine

# ... rest of file ...

volumes:
  output-data:  # Keep this
```

---

### 10. Health Check Will Fail
**File**: `docker-compose.yml:21`
**Issue**: `curl` not installed in Python slim image

**Fix**:
```yaml
healthcheck:
  test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

---

## 🔧 APPLICATION SCRIPT

Create `scripts/apply_critical_fixes.sh`:

```bash
#!/bin/bash
# Apply all critical fixes automatically

set -e

echo "Applying critical fixes..."

# Fix 1: Update requirements.txt with specific Python version
echo "python_requires>=3.11" >> requirements.txt

# Fix 2: Create missing __init__.py files
touch generator/attack_traces/__init__.py
echo '"""IAM privilege escalation scenario."""
from .generator import generate_iam_privilege_escalation_scenario
__all__ = ["generate_iam_privilege_escalation_scenario"]' > generator/attack_traces/iam_priv_escalation/__init__.py

echo '"""Container escape scenario."""
from .generator import generate_container_escape_scenario
__all__ = ["generate_container_escape_scenario"]' > generator/attack_traces/container_escape/__init__.py

echo '"""Credential stuffing scenario."""
from .generator import generate_credential_stuffing_scenario
__all__ = ["generate_credential_stuffing_scenario"]' > generator/attack_traces/cred_stuffing/__init__.py

# Fix 3: Update .env.example with security configs
cat >> .env.example << 'EOF'

# Security
ALLOWED_ORIGINS=http://localhost:3000
API_KEY=generate-secure-key-here
EOF

echo "✓ Critical fixes applied!"
echo ""
echo "MANUAL STEPS REQUIRED:"
echo "1. Review and apply code changes from CRITICAL_FIXES.md"
echo "2. Generate secure API key: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
echo "3. Update .env with generated API key"
echo "4. Test all scenarios after applying fixes"
```

---

## ✅ VERIFICATION CHECKLIST

After applying fixes, verify:

- [ ] Python version check: `python --version` shows 3.11+
- [ ] All `__init__.py` files created
- [ ] CORS only allows specific origins
- [ ] API key authentication working
- [ ] Temp files cleaned up after analysis
- [ ] Docker containers run as non-root
- [ ] Health checks passing
- [ ] All scenarios generate valid telemetry
- [ ] Analysis pipeline completes without errors
- [ ] Reports generated successfully

---

## 🚀 DEPLOYMENT CHECKLIST

Before going live:

- [ ] All critical fixes applied
- [ ] Generated strong API key (32+ characters)
- [ ] Set `ALLOWED_ORIGINS` to production domains only
- [ ] Enable HTTPS/TLS
- [ ] Set up rate limiting
- [ ] Configure logging and monitoring
- [ ] Run security scan: `bandit -r generator analysis_engine`
- [ ] Run full test suite: `pytest`
- [ ] Load test API endpoints
- [ ] Document all configuration changes

---

**Priority**: Apply fixes 1-4 immediately for any deployment
**Timeline**: All fixes can be applied in 2-4 hours
**Testing**: Run `./scripts/run_all_scenarios.sh` after applying fixes
