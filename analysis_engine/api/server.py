"""
FastAPI server for analysis engine with security enhancements.
"""
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pathlib import Path
from typing import Any, Dict
import tempfile
import logging
import json
import os
import time
import asyncio

from analysis_engine.pipeline import ThreatHuntingPipeline
from analysis_engine.api.auth import verify_api_key, verify_admin_key
from analysis_engine.api.models import (
    HealthResponse, AnalysisResult, GenerateScenarioRequest,
    GenerateScenarioResponse, ScenarioListResponse, ErrorResponse,
    AnalyzeDataRequest, ScenarioInfo, ScenarioName
)
from analysis_engine.api.security import (
    RequestIDMiddleware, SecurityHeadersMiddleware,
    FileValidator, AuditLogger, get_client_ip
)
from analysis_engine.detection import DetectionRuleTester, RuleTestResult, RuleFormat
from analysis_engine.api.websocket import (
    manager as ws_manager,
    StreamingScenarioGenerator,
    StreamingAnalyzer,
    heartbeat_task
)
from config import get_settings

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Monitoring
from analysis_engine.monitoring import (
    get_metrics,
    get_content_type,
    http_requests_total,
    http_request_duration_seconds,
    record_file_upload,
    record_event_processed,
    record_health_check,
    collect_system_metrics,
    api_logger,
    set_correlation_id,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="AI Threat Hunting Simulator API",
    description="Analysis engine API for threat hunting",
    version="3.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Load configuration
settings = get_settings()

# Enable CORS with proper security
ALLOWED_ORIGINS = settings.allowed_origins if isinstance(settings.allowed_origins, list) else settings.allowed_origins.split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Add security middleware
app.add_middleware(SecurityHeadersMiddleware, enable_hsts=os.getenv("ENABLE_HSTS", "false").lower() == "true")
app.add_middleware(RequestIDMiddleware)

# Initialize pipeline with LLM and threat intelligence
pipeline = ThreatHuntingPipeline(
    time_window_minutes=settings.correlation_time_window_minutes,
    min_events_for_session=settings.min_events_for_alert,
    risk_threshold=settings.risk_score_threshold,
    enable_database=True,
    database_url=settings.db_connection_string,
    llm_provider_type=settings.llm_provider if settings.llm_provider.lower() not in ["none", ""] else None,
    llm_api_key=settings.openai_api_key if settings.llm_provider == "openai" else settings.anthropic_api_key,
    llm_model=settings.llm_model,
    enable_threat_intel=settings.enable_threat_intel,
    threat_intel_config=settings if settings.enable_threat_intel else None
)

# Initialize detection rule tester
rule_tester = DetectionRuleTester()

# Initialize cache if enabled
try:
    from analysis_engine.cache import init_cache, CacheConfig, get_cache
    if settings.redis_enabled:
        cache_config = CacheConfig(
            enabled=True,
            redis_host=settings.redis_host,
            redis_port=settings.redis_port,
            redis_db=settings.redis_db,
            redis_password=settings.redis_password,
            default_ttl=settings.redis_cache_ttl,
            max_connections=settings.redis_max_connections
        )
        cache = init_cache(cache_config)
        logger.info("Redis cache initialized successfully")
    else:
        cache_config = CacheConfig(enabled=False)
        cache = init_cache(cache_config)
        logger.info("Redis caching disabled")
except Exception as e:
    logger.warning(f"Cache initialization failed: {e}. Running without cache.")
    cache = None

# Request tracking middleware
@app.middleware("http")
async def track_requests(request: Request, call_next):
    """Middleware to track all HTTP requests with metrics and logging."""
    # Generate correlation ID
    correlation_id = set_correlation_id()

    # Track request start time
    start_time = time.time()

    # Log request
    api_logger.info(
        f"Request started: {request.method} {request.url.path}",
        method=request.method,
        path=request.url.path,
        client=request.client.host if request.client else "unknown",
        correlation_id=correlation_id
    )

    # Process request
    try:
        response = await call_next(request)
        status_code = response.status_code

        # Track successful request
        http_requests_total.labels(
            method=request.method,
            endpoint=request.url.path,
            status_code=status_code
        ).inc()

        return response

    except Exception as e:
        # Track failed request
        http_requests_total.labels(
            method=request.method,
            endpoint=request.url.path,
            status_code=500
        ).inc()

        api_logger.error(
            f"Request failed: {request.method} {request.url.path}",
            error=str(e),
            error_type=type(e).__name__,
            correlation_id=correlation_id
        )
        raise

    finally:
        # Record duration
        duration = time.time() - start_time
        http_request_duration_seconds.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(duration)

        api_logger.performance(
            f"Request completed: {request.method} {request.url.path}",
            duration=duration,
            operation="http_request",
            method=request.method,
            path=request.url.path
        )


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "AI Threat Hunting Simulator API",
        "version": "3.0.0",
        "status": "operational",
        "documentation": "/docs"
    }


@app.get("/health")
async def health():
    """
    Health check endpoint with component status.

    Returns health status for all major components.
    """
    health_status = {
        "status": "healthy",
        "version": "3.0.0",
        "timestamp": time.time(),
        "components": {}
    }

    # Check pipeline
    start_time = time.time()
    try:
        # Simple check - ensure pipeline is initialized
        pipeline_healthy = pipeline is not None
        health_status["components"]["pipeline"] = {
            "status": "healthy" if pipeline_healthy else "unhealthy",
            "check_duration": time.time() - start_time
        }
        record_health_check("pipeline", pipeline_healthy, time.time() - start_time)
    except Exception as e:
        health_status["components"]["pipeline"] = {
            "status": "unhealthy",
            "error": str(e),
            "check_duration": time.time() - start_time
        }
        record_health_check("pipeline", False, time.time() - start_time)
        health_status["status"] = "degraded"

    # Check system resources
    start_time = time.time()
    try:
        import psutil
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        system_healthy = mem.percent < 90 and disk.percent < 90
        health_status["components"]["system"] = {
            "status": "healthy" if system_healthy else "degraded",
            "memory_percent": mem.percent,
            "disk_percent": disk.percent,
            "check_duration": time.time() - start_time
        }
        record_health_check("system", system_healthy, time.time() - start_time)

        if not system_healthy:
            health_status["status"] = "degraded"

    except ImportError:
        health_status["components"]["system"] = {
            "status": "unknown",
            "message": "psutil not available"
        }
    except Exception as e:
        health_status["components"]["system"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health_status["status"] = "degraded"

    # Update system metrics
    collect_system_metrics()

    return health_status


@app.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint.

    Returns metrics in Prometheus text format for scraping by monitoring systems.
    """
    # Collect latest system metrics
    collect_system_metrics()

    # Return metrics in Prometheus format
    return Response(
        content=get_metrics(),
        media_type=get_content_type()
    )


@app.get("/stats")
async def stats():
    """
    Statistics endpoint.

    Returns current statistics in JSON format for dashboards and monitoring.
    """
    from prometheus_client import REGISTRY

    stats_data = {
        "timestamp": time.time(),
        "version": "3.0.0",
        "metrics": {}
    }

    # Collect current metrics from Prometheus registry
    for metric in REGISTRY.collect():
        metric_name = metric.name

        # Skip internal Prometheus metrics
        if metric_name.startswith("python_") or metric_name.startswith("process_"):
            continue

        metric_data = {
            "type": metric.type,
            "documentation": metric.documentation,
            "samples": []
        }

        for sample in metric.samples:
            metric_data["samples"].append({
                "name": sample.name,
                "labels": sample.labels,
                "value": sample.value
            })

        stats_data["metrics"][metric_name] = metric_data

    # Add summary statistics
    stats_data["summary"] = _generate_stats_summary(stats_data["metrics"])

    return stats_data


@app.get("/cache/stats")
@limiter.limit("30/minute")
async def cache_stats(request: Request) -> Dict[str, Any]:
    """
    Get cache statistics.

    Args:
        request: FastAPI request object

    Returns:
        Cache statistics including hit rate and connection status
    """
    cache = get_cache()
    if cache:
        return cache.get_stats()
    else:
        return {
            "enabled": False,
            "connected": False,
            "message": "Cache not initialized"
        }


def _generate_stats_summary(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate summary statistics from metrics.

    Args:
        metrics: Dictionary of metrics

    Returns:
        Summary statistics
    """
    summary = {}

    try:
        # Analysis requests
        if "analysis_requests_total" in metrics:
            total_requests = 0
            success_requests = 0
            failed_requests = 0

            for sample in metrics["analysis_requests_total"]["samples"]:
                total_requests += sample["value"]
                if sample["labels"].get("status") == "success":
                    success_requests += sample["value"]
                elif sample["labels"].get("status") == "failure":
                    failed_requests += sample["value"]

            summary["analysis"] = {
                "total_requests": total_requests,
                "success_requests": success_requests,
                "failed_requests": failed_requests,
                "success_rate": (success_requests / total_requests * 100) if total_requests > 0 else 0
            }

        # Events processed
        if "events_processed_total" in metrics:
            total_events = sum(
                sample["value"]
                for sample in metrics["events_processed_total"]["samples"]
            )
            summary["events"] = {
                "total_processed": total_events
            }

        # Sessions detected
        if "sessions_detected_total" in metrics:
            total_sessions = 0
            malicious_sessions = 0

            for sample in metrics["sessions_detected_total"]["samples"]:
                total_sessions += sample["value"]
                if sample["labels"].get("is_malicious") == "true":
                    malicious_sessions += sample["value"]

            summary["sessions"] = {
                "total_detected": total_sessions,
                "malicious_detected": malicious_sessions,
                "malicious_rate": (malicious_sessions / total_sessions * 100) if total_sessions > 0 else 0
            }

        # Current jobs
        if "current_analysis_jobs" in metrics:
            current_jobs = metrics["current_analysis_jobs"]["samples"][0]["value"] if metrics["current_analysis_jobs"]["samples"] else 0
            summary["current_jobs"] = current_jobs

        # HTTP requests
        if "http_requests_total" in metrics:
            total_http = sum(
                sample["value"]
                for sample in metrics["http_requests_total"]["samples"]
            )
            summary["http"] = {
                "total_requests": total_http
            }

        # Errors
        if "errors_total" in metrics:
            total_errors = sum(
                sample["value"]
                for sample in metrics["errors_total"]["samples"]
            )
            summary["errors"] = {
                "total_errors": total_errors
            }

    except Exception as e:
        logger.error(f"Error generating stats summary: {e}")

    return summary


@app.post("/analyze/upload", dependencies=[Depends(verify_api_key)], response_model=AnalysisResult)
@limiter.limit("10/minute")
async def analyze_upload(
    request: Request,
    file: UploadFile = File(...)
) -> AnalysisResult:
    """
    Analyze uploaded telemetry file with comprehensive security validation.

    Args:
        request: FastAPI request object
        file: Uploaded telemetry file (JSONL or JSON)

    Returns:
        Analysis results with validated response model

    Raises:
        HTTPException: If file validation fails or analysis fails
    """
    tmp_path = None

    try:
        # Comprehensive file validation with security checks
        validation_result = await FileValidator.validate_upload(
            file,
            max_size=settings.max_upload_size_mb * 1024 * 1024,
            allowed_extensions={'.jsonl', '.json', '.txt', '.log'}
        )

        # Audit log the file upload
        client_ip = get_client_ip(request)
        request_id = getattr(request.state, 'request_id', 'unknown')
        AuditLogger.log_file_upload(
            request_id=request_id,
            filename=validation_result['filename'],
            size_bytes=validation_result['size_bytes'],
            client_ip=client_ip
        )

        logger.info(
            f"Analyzing uploaded file: {file.filename} "
            f"({validation_result['size_bytes']} bytes, "
            f"SHA256: {validation_result['sha256'][:16]}...)"
        )

        # Save uploaded file to secure temp location
        with tempfile.NamedTemporaryFile(
            mode='wb',
            suffix=Path(file.filename).suffix.lower(),
            delete=False,
            dir=tempfile.gettempdir()
        ) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = Path(tmp_file.name)

        # Record file upload metric
        record_file_upload(validation_result['size_bytes'])

        # Analyze with error handling
        start_time = time.time()
        results = pipeline.analyze_telemetry_file(tmp_path)
        analysis_duration = time.time() - start_time

        # Add duration to results
        results['analysis_duration_seconds'] = round(analysis_duration, 2)

        # Record events processed
        if "total_events" in results:
            record_event_processed("upload", results["total_events"])

        return AnalysisResult(**results)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}",
            headers={"X-Request-ID": getattr(request.state, 'request_id', 'unknown')}
        )

    finally:
        # Always cleanup temp file
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
                logger.debug(f"Cleaned up temp file: {tmp_path}")
            except Exception as e:
                logger.error(f"Failed to cleanup temp file {tmp_path}: {e}")


@app.post("/analyze/data", dependencies=[Depends(verify_api_key)])
@limiter.limit("20/minute")
async def analyze_data(request: Request, events: list) -> Dict[str, Any]:
    """
    Analyze telemetry events provided as JSON.

    Args:
        request: FastAPI request object
        events: List of telemetry events

    Returns:
        Analysis results

    Raises:
        HTTPException: If events are invalid or analysis fails
    """
    tmp_path = None

    try:
        # Validate input
        if not events:
            raise HTTPException(status_code=400, detail="No events provided")

        if not isinstance(events, list):
            raise HTTPException(status_code=400, detail="Events must be a list")

        # Limit number of events
        max_events = int(os.getenv("MAX_EVENTS_PER_REQUEST", "10000"))
        if len(events) > max_events:
            raise HTTPException(
                status_code=400,
                detail=f"Too many events. Maximum: {max_events}"
            )

        logger.info(f"Analyzing {len(events)} events from API request")

        # Record events being processed
        record_event_processed("api", len(events))

        # Write events to temp file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.jsonl',
            delete=False
        ) as tmp_file:
            for event in events:
                tmp_file.write(json.dumps(event) + '\n')
            tmp_path = Path(tmp_file.name)

        # Analyze
        results = pipeline.analyze_telemetry_file(tmp_path)

        return results

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        # Always cleanup temp file
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception as e:
                logger.error(f"Failed to cleanup temp file: {e}")


@app.get("/scenarios")
@limiter.limit("30/minute")
async def list_scenarios(request: Request) -> Dict[str, Any]:
    """
    List available pre-generated scenarios.

    Args:
        request: FastAPI request object

    Returns:
        List of scenario metadata
    """
    scenarios_dir = Path("output/scenarios")

    if not scenarios_dir.exists():
        return {"scenarios": []}

    scenarios = []

    for scenario_path in scenarios_dir.iterdir():
        if scenario_path.is_dir():
            metadata_file = scenario_path / "metadata.json"

            if metadata_file.exists():
                with open(metadata_file) as f:
                    metadata = json.load(f)
                    scenarios.append({
                        "name": scenario_path.name,
                        **metadata
                    })

    return {"scenarios": scenarios}


@app.get("/scenarios/{scenario_name}")
@limiter.limit("30/minute")
async def get_scenario(request: Request, scenario_name: str) -> Dict[str, Any]:
    """
    Get analysis results for a specific scenario.

    Args:
        request: FastAPI request object
        scenario_name: Name of the scenario

    Returns:
        Scenario analysis results

    Raises:
        HTTPException: If scenario not found
    """
    # Sanitize scenario name to prevent path traversal
    scenario_name = scenario_name.replace("..", "").replace("/", "").replace("\\", "")

    scenario_path = Path("output/scenarios") / scenario_name

    if not scenario_path.exists():
        raise HTTPException(status_code=404, detail="Scenario not found")

    # Check for existing analysis
    analysis_file = scenario_path / "analysis_report.json"

    if analysis_file.exists():
        with open(analysis_file) as f:
            return json.load(f)

    # Otherwise analyze on the fly
    telemetry_file = scenario_path / "telemetry.jsonl"

    if not telemetry_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Telemetry file not found for scenario"
        )

    results = pipeline.analyze_telemetry_file(telemetry_file, scenario_path)
    return results


@app.delete("/scenarios/{scenario_name}", dependencies=[Depends(verify_admin_key)])
async def delete_scenario(scenario_name: str) -> Dict[str, str]:
    """
    Delete a scenario (admin only).

    Args:
        scenario_name: Name of the scenario to delete

    Returns:
        Success message

    Raises:
        HTTPException: If scenario not found or deletion fails
    """
    import shutil

    # Sanitize scenario name
    scenario_name = scenario_name.replace("..", "").replace("/", "").replace("\\", "")

    scenario_path = Path("output/scenarios") / scenario_name

    if not scenario_path.exists():
        raise HTTPException(status_code=404, detail="Scenario not found")

    try:
        shutil.rmtree(scenario_path)
        logger.info(f"Deleted scenario: {scenario_name}")
        return {"status": "success", "message": f"Scenario '{scenario_name}' deleted"}
    except Exception as e:
        logger.error(f"Failed to delete scenario {scenario_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete scenario: {str(e)}")


# WebSocket Endpoints

@app.websocket("/ws/scenario/{scenario_name}")
async def websocket_scenario_stream(websocket: WebSocket, scenario_name: str):
    """
    WebSocket endpoint for real-time scenario generation streaming.

    Args:
        websocket: WebSocket connection
        scenario_name: Name of scenario to generate

    Streams:
        - Scenario start event
        - Event batches as they're generated
        - Completion summary
    """
    await ws_manager.connect(websocket, client_id=f"scenario_{scenario_name}")

    try:
        # Subscribe to scenario topic
        await ws_manager.subscribe(websocket, f"scenario_{scenario_name}")

        # Create streaming generator
        generator = StreamingScenarioGenerator(websocket, scenario_name)

        # Stream scenario generation
        await generator.stream_scenario()

        # Keep connection open for potential client messages
        while True:
            try:
                data = await websocket.receive_text()
                # Handle client commands if needed
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: scenario_{scenario_name}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
        await websocket.send_json({
            "type": "error",
            "error": str(e)
        })
    finally:
        ws_manager.disconnect(websocket)


@app.websocket("/ws/analysis")
async def websocket_analysis_stream(websocket: WebSocket):
    """
    WebSocket endpoint for real-time analysis streaming.

    Accepts telemetry path and streams analysis progress.

    Streams:
        - Analysis start event
        - Progress updates
        - Detected sessions
        - Final results
    """
    await ws_manager.connect(websocket, client_id="analysis_client")

    try:
        # Wait for client to send telemetry path
        data = await websocket.receive_json()

        if "telemetry_path" not in data:
            await websocket.send_json({
                "type": "error",
                "error": "telemetry_path required"
            })
            return

        telemetry_path = data["telemetry_path"]

        # Create streaming analyzer
        analyzer = StreamingAnalyzer(websocket, pipeline)

        # Stream analysis
        await analyzer.stream_analysis(telemetry_path)

        # Keep connection open
        while True:
            try:
                msg = await websocket.receive_text()
                if msg == "ping":
                    await websocket.send_json({"type": "pong"})
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected: analysis")
    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
        await websocket.send_json({
            "type": "error",
            "error": str(e)
        })
    finally:
        ws_manager.disconnect(websocket)


@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    """
    WebSocket endpoint for live telemetry feed.

    Broadcasts all events and analysis updates to connected clients.
    """
    await ws_manager.connect(websocket, client_id="live_feed")

    try:
        # Subscribe to all topics
        await ws_manager.subscribe(websocket, "live_feed")

        # Send connection confirmation
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to live feed"
        })

        # Keep connection alive
        while True:
            try:
                data = await websocket.receive_text()

                # Handle client commands
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
                elif data == "stats":
                    stats = ws_manager.get_stats()
                    await websocket.send_json({
                        "type": "stats",
                        "data": stats
                    })

            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected: live_feed")
    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
    finally:
        ws_manager.disconnect(websocket)


@app.get("/ws/stats")
@limiter.limit("30/minute")
async def websocket_stats(request: Request) -> Dict[str, Any]:
    """
    Get WebSocket connection statistics.

    Args:
        request: FastAPI request object

    Returns:
        WebSocket statistics
    """
    return ws_manager.get_stats()


# Start background heartbeat task
@app.on_event("startup")
async def start_heartbeat():
    """Start WebSocket heartbeat task on app startup."""
    asyncio.create_task(heartbeat_task())
    logger.info("WebSocket heartbeat task started")


# Detection Rule Testing Endpoints

@app.post("/detection/test-rule", dependencies=[Depends(verify_api_key)])
@limiter.limit("10/minute")
async def test_detection_rule(
    request: Request,
    rule_content: str,
    events: list,
    ground_truth: list = None
) -> Dict[str, Any]:
    """
    Test a Sigma detection rule against telemetry events.

    Args:
        request: FastAPI request object
        rule_content: Sigma rule YAML content as string
        events: List of telemetry events to test against
        ground_truth: Optional list of event IDs that should match (for accuracy metrics)

    Returns:
        Rule test results with precision, recall, F1 score

    Raises:
        HTTPException: If rule is invalid or testing fails
    """
    try:
        # Validate inputs
        if not rule_content or not isinstance(rule_content, str):
            raise HTTPException(status_code=400, detail="Rule content is required")

        if not events or not isinstance(events, list):
            raise HTTPException(status_code=400, detail="Events list is required")

        # Limit number of events
        max_events = 10000
        if len(events) > max_events:
            raise HTTPException(
                status_code=400,
                detail=f"Too many events. Maximum: {max_events}"
            )

        # Convert ground_truth to set if provided
        ground_truth_set = set(ground_truth) if ground_truth else None

        # Test the rule
        start_time = time.time()
        result = rule_tester.test_sigma_rule(
            rule_content=rule_content,
            events=events,
            ground_truth=ground_truth_set
        )
        test_duration = time.time() - start_time

        # Log the test
        client_ip = get_client_ip(request)
        request_id = getattr(request.state, 'request_id', 'unknown')
        logger.info(
            f"Detection rule tested: {result.total_events} events, "
            f"{result.matched_events} matches, precision={result.precision:.3f}, "
            f"recall={result.recall:.3f}",
            extra={
                "request_id": request_id,
                "client_ip": client_ip,
                "test_duration": test_duration
            }
        )

        # Return results
        return {
            "status": "success",
            "rule_format": result.rule_format.value,
            "total_events": result.total_events,
            "matched_events": result.matched_events,
            "true_positives": result.true_positives,
            "false_positives": result.false_positives,
            "false_negatives": result.false_negatives,
            "true_negatives": result.true_negatives,
            "precision": round(result.precision, 4),
            "recall": round(result.recall, 4),
            "f1_score": round(result.f1_score, 4),
            "accuracy": round(result.accuracy, 4),
            "test_duration_seconds": round(test_duration, 3),
            "coverage_report": result.coverage_report
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Rule testing failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Rule testing failed: {str(e)}"
        )


@app.post("/detection/test-rules-batch", dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
async def test_rules_batch(
    request: Request,
    rules: list,
    events: list
) -> Dict[str, Any]:
    """
    Test multiple Sigma rules in batch against telemetry events.

    Args:
        request: FastAPI request object
        rules: List of dicts with 'name' and 'content' keys
        events: List of telemetry events to test against

    Returns:
        Batch test results for all rules

    Raises:
        HTTPException: If inputs are invalid or testing fails
    """
    try:
        # Validate inputs
        if not rules or not isinstance(rules, list):
            raise HTTPException(status_code=400, detail="Rules list is required")

        if not events or not isinstance(events, list):
            raise HTTPException(status_code=400, detail="Events list is required")

        # Limit batch size
        max_rules = 50
        if len(rules) > max_rules:
            raise HTTPException(
                status_code=400,
                detail=f"Too many rules. Maximum: {max_rules}"
            )

        max_events = 10000
        if len(events) > max_events:
            raise HTTPException(
                status_code=400,
                detail=f"Too many events. Maximum: {max_events}"
            )

        # Test all rules
        start_time = time.time()
        results = []

        for rule_def in rules:
            if not isinstance(rule_def, dict) or 'content' not in rule_def:
                results.append({
                    "name": rule_def.get('name', 'unknown'),
                    "status": "error",
                    "error": "Invalid rule format - 'content' field required"
                })
                continue

            try:
                result = rule_tester.test_sigma_rule(
                    rule_content=rule_def['content'],
                    events=events
                )

                results.append({
                    "name": rule_def.get('name', 'unknown'),
                    "status": "success",
                    "matched_events": result.matched_events,
                    "precision": round(result.precision, 4),
                    "recall": round(result.recall, 4),
                    "f1_score": round(result.f1_score, 4),
                    "accuracy": round(result.accuracy, 4)
                })

            except Exception as e:
                results.append({
                    "name": rule_def.get('name', 'unknown'),
                    "status": "error",
                    "error": str(e)
                })

        test_duration = time.time() - start_time

        # Log batch test
        client_ip = get_client_ip(request)
        request_id = getattr(request.state, 'request_id', 'unknown')
        logger.info(
            f"Batch rule test: {len(rules)} rules against {len(events)} events",
            extra={
                "request_id": request_id,
                "client_ip": client_ip,
                "test_duration": test_duration
            }
        )

        return {
            "status": "success",
            "total_rules": len(rules),
            "total_events": len(events),
            "test_duration_seconds": round(test_duration, 3),
            "results": results
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch rule testing failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Batch rule testing failed: {str(e)}"
        )


@app.get("/detection/rules")
@limiter.limit("30/minute")
async def list_detection_rules(request: Request) -> Dict[str, Any]:
    """
    List all available Sigma detection rules.

    Args:
        request: FastAPI request object

    Returns:
        List of available detection rules with metadata
    """
    rules_dir = Path("detection_rules/sigma")

    if not rules_dir.exists():
        return {"rules": []}

    rules = []

    for rule_file in rules_dir.glob("*.yml"):
        try:
            with open(rule_file, 'r') as f:
                content = f.read()

                # Parse basic metadata from YAML
                import yaml
                rule_data = yaml.safe_load(content)

                rules.append({
                    "name": rule_file.stem,
                    "file": rule_file.name,
                    "title": rule_data.get('title', 'Unknown'),
                    "description": rule_data.get('description', ''),
                    "level": rule_data.get('level', 'medium'),
                    "tags": rule_data.get('tags', []),
                    "author": rule_data.get('author', ''),
                    "status": rule_data.get('status', 'experimental')
                })

        except Exception as e:
            logger.warning(f"Failed to parse rule {rule_file}: {e}")
            continue

    return {
        "total_rules": len(rules),
        "rules": sorted(rules, key=lambda x: x['name'])
    }


@app.get("/detection/rules/{rule_name}")
@limiter.limit("30/minute")
async def get_detection_rule(request: Request, rule_name: str) -> Dict[str, Any]:
    """
    Get a specific Sigma detection rule.

    Args:
        request: FastAPI request object
        rule_name: Name of the rule (without .yml extension)

    Returns:
        Rule content and metadata

    Raises:
        HTTPException: If rule not found
    """
    # Sanitize rule name
    rule_name = rule_name.replace("..", "").replace("/", "").replace("\\", "")

    rule_file = Path("detection_rules/sigma") / f"{rule_name}.yml"

    if not rule_file.exists():
        raise HTTPException(status_code=404, detail="Detection rule not found")

    try:
        with open(rule_file, 'r') as f:
            content = f.read()

            # Parse metadata
            import yaml
            rule_data = yaml.safe_load(content)

            return {
                "name": rule_name,
                "file": rule_file.name,
                "content": content,
                "metadata": {
                    "title": rule_data.get('title', 'Unknown'),
                    "description": rule_data.get('description', ''),
                    "level": rule_data.get('level', 'medium'),
                    "tags": rule_data.get('tags', []),
                    "author": rule_data.get('author', ''),
                    "status": rule_data.get('status', 'experimental'),
                    "references": rule_data.get('references', [])
                }
            }

    except Exception as e:
        logger.error(f"Failed to read rule {rule_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read rule: {str(e)}"
        )


@app.post("/detection/generate-rule", dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
async def generate_detection_rule(
    request: Request,
    scenario_name: str,
    events: list = None
) -> Dict[str, Any]:
    """
    Auto-generate a Sigma detection rule from a scenario or events.

    Args:
        request: FastAPI request object
        scenario_name: Name of the scenario to generate rule from
        events: Optional list of telemetry events to analyze

    Returns:
        Generated Sigma rule content

    Raises:
        HTTPException: If generation fails
    """
    try:
        # If events not provided, load from scenario
        if not events:
            scenario_path = Path("output/scenarios") / scenario_name / "telemetry.jsonl"

            if not scenario_path.exists():
                raise HTTPException(
                    status_code=404,
                    detail=f"Scenario '{scenario_name}' not found"
                )

            events = []
            with open(scenario_path, 'r') as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))

        if not events:
            raise HTTPException(status_code=400, detail="No events to analyze")

        # Generate rule from events
        generated_rule = rule_tester.generate_sigma_rule_from_events(
            scenario_name=scenario_name,
            events=events
        )

        # Log generation
        client_ip = get_client_ip(request)
        request_id = getattr(request.state, 'request_id', 'unknown')
        logger.info(
            f"Generated detection rule for scenario: {scenario_name}",
            extra={
                "request_id": request_id,
                "client_ip": client_ip,
                "event_count": len(events)
            }
        )

        return {
            "status": "success",
            "scenario_name": scenario_name,
            "event_count": len(events),
            "rule_content": generated_rule
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Rule generation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Rule generation failed: {str(e)}"
        )


# Database endpoints (if database is available)
try:
    from analysis_engine.database import (
        DatabaseConfig,
        DatabaseManager,
        AnalysisRepository,
        SessionRepository,
        IOCRepository
    )
    DATABASE_AVAILABLE = True

    # Initialize database if configured
    db_url = os.getenv("DB_CONNECTION_STRING")
    if db_url:
        db_config = DatabaseConfig.from_url(db_url)
        db_manager = DatabaseManager(db_config)

        @app.get("/database/analyses")
        @limiter.limit("30/minute")
        async def list_analyses(
            request: Request,
            limit: int = 50,
            offset: int = 0
        ) -> Dict[str, Any]:
            """
            List all analysis runs from database.

            Args:
                request: FastAPI request object
                limit: Maximum number of results
                offset: Number of results to skip

            Returns:
                List of analysis runs
            """
            try:
                with db_manager.session_scope() as session:
                    repo = AnalysisRepository(session)
                    runs = repo.list_analysis_runs(limit=limit, offset=offset)
                    total = repo.count_analysis_runs()

                    return {
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                        "analyses": [
                            {
                                "id": run.id,
                                "scenario_name": run.scenario_name,
                                "num_events": run.num_events,
                                "num_sessions": run.num_sessions,
                                "num_suspicious_sessions": run.num_suspicious_sessions,
                                "created_at": run.created_at.isoformat(),
                                "risk_threshold": run.risk_threshold
                            }
                            for run in runs
                        ]
                    }
            except Exception as e:
                logger.error(f"Database query failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/database/analyses/{run_id}")
        @limiter.limit("30/minute")
        async def get_analysis(request: Request, run_id: int) -> Dict[str, Any]:
            """
            Get detailed analysis run information.

            Args:
                request: FastAPI request object
                run_id: Analysis run ID

            Returns:
                Analysis run details

            Raises:
                HTTPException: If analysis run not found
            """
            try:
                with db_manager.session_scope() as session:
                    repo = AnalysisRepository(session)
                    run = repo.get_analysis_run(run_id, include_sessions=True)

                    if not run:
                        raise HTTPException(status_code=404, detail="Analysis run not found")

                    return {
                        "id": run.id,
                        "scenario_name": run.scenario_name,
                        "num_events": run.num_events,
                        "num_sessions": run.num_sessions,
                        "num_suspicious_sessions": run.num_suspicious_sessions,
                        "created_at": run.created_at.isoformat(),
                        "time_window_minutes": run.time_window_minutes,
                        "min_events_for_session": run.min_events_for_session,
                        "risk_threshold": run.risk_threshold,
                        "telemetry_file_path": run.telemetry_file_path,
                        "analysis_duration_seconds": run.analysis_duration_seconds,
                        "results": run.results,
                        "sessions": [
                            {
                                "id": s.id,
                                "session_id": s.session_id,
                                "principal": s.principal,
                                "risk_score": s.risk_score,
                                "is_malicious": s.is_malicious,
                                "event_count": s.event_count
                            }
                            for s in run.detected_sessions
                        ]
                    }
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Database query failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/database/sessions/{session_id}/iocs")
        @limiter.limit("30/minute")
        async def get_session_iocs(request: Request, session_id: int) -> Dict[str, Any]:
            """
            Get IOCs for a specific detected session.

            Args:
                request: FastAPI request object
                session_id: Detected session ID

            Returns:
                List of IOCs

            Raises:
                HTTPException: If session not found
            """
            try:
                with db_manager.session_scope() as session:
                    ioc_repo = IOCRepository(session)
                    iocs = ioc_repo.get_iocs_by_session(session_id)

                    return {
                        "session_id": session_id,
                        "ioc_count": len(iocs),
                        "iocs": [
                            {
                                "id": ioc.id,
                                "type": ioc.ioc_type,
                                "value": ioc.value,
                                "severity": ioc.severity,
                                "description": ioc.description,
                                "first_seen": ioc.first_seen.isoformat()
                            }
                            for ioc in iocs
                        ]
                    }
            except Exception as e:
                logger.error(f"Database query failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        logger.info("Database endpoints enabled")

except ImportError:
    DATABASE_AVAILABLE = False
    logger.info("Database not available - database endpoints disabled")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
