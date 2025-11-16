"""
Prometheus metrics for performance monitoring.

Provides comprehensive metrics tracking for the analysis engine including
request counts, durations, event processing, and resource utilization.
"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from functools import wraps
from typing import Callable, Any
import time
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# Prometheus Metrics Definitions
# ============================================================================

# Analysis request metrics
analysis_requests_total = Counter(
    'analysis_requests_total',
    'Total number of analysis requests',
    ['scenario', 'status']
)

analysis_duration_seconds = Histogram(
    'analysis_duration_seconds',
    'Duration of analysis requests in seconds',
    ['scenario'],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, float('inf'))
)

# Event processing metrics
events_processed_total = Counter(
    'events_processed_total',
    'Total number of telemetry events processed',
    ['event_source']
)

events_processing_errors_total = Counter(
    'events_processing_errors_total',
    'Total number of event processing errors',
    ['error_type']
)

# Session detection metrics
sessions_detected_total = Counter(
    'sessions_detected_total',
    'Total number of sessions detected',
    ['is_malicious']
)

sessions_analysis_duration_seconds = Histogram(
    'sessions_analysis_duration_seconds',
    'Duration of individual session analysis in seconds',
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, float('inf'))
)

# Resource utilization metrics
current_analysis_jobs = Gauge(
    'current_analysis_jobs',
    'Number of currently running analysis jobs'
)

memory_usage_bytes = Gauge(
    'memory_usage_bytes',
    'Current memory usage in bytes',
    ['type']
)

file_upload_size_bytes = Histogram(
    'file_upload_size_bytes',
    'Size of uploaded files in bytes',
    buckets=(1024, 10240, 102400, 1048576, 10485760, 52428800, 104857600, float('inf'))
)

# AI Agent metrics
llm_requests_total = Counter(
    'llm_requests_total',
    'Total number of LLM API requests',
    ['agent', 'model', 'status']
)

llm_request_duration_seconds = Histogram(
    'llm_request_duration_seconds',
    'Duration of LLM API requests in seconds',
    ['agent', 'model'],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0, float('inf'))
)

llm_tokens_used_total = Counter(
    'llm_tokens_used_total',
    'Total number of tokens used in LLM requests',
    ['agent', 'model', 'token_type']
)

# Database metrics
database_queries_total = Counter(
    'database_queries_total',
    'Total number of database queries',
    ['operation', 'table', 'status']
)

database_query_duration_seconds = Histogram(
    'database_query_duration_seconds',
    'Duration of database queries in seconds',
    ['operation', 'table'],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, float('inf'))
)

# HTTP endpoint metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'status_code']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'Duration of HTTP requests in seconds',
    ['method', 'endpoint'],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, float('inf'))
)

# IOC extraction metrics
iocs_extracted_total = Counter(
    'iocs_extracted_total',
    'Total number of IOCs extracted',
    ['ioc_type']
)

# Error tracking
errors_total = Counter(
    'errors_total',
    'Total number of errors',
    ['error_type', 'component']
)

# Health check metrics
health_check_status = Gauge(
    'health_check_status',
    'Health check status (1 = healthy, 0 = unhealthy)',
    ['component']
)

health_check_duration_seconds = Histogram(
    'health_check_duration_seconds',
    'Duration of health checks in seconds',
    ['component'],
    buckets=(0.001, 0.01, 0.1, 0.5, 1.0, 5.0, float('inf'))
)


# ============================================================================
# Decorator Functions
# ============================================================================

def track_analysis(scenario: str = "unknown"):
    """
    Decorator to automatically track analysis requests with Prometheus metrics.

    Tracks:
    - Total requests (with status: success/failure)
    - Request duration
    - Active jobs gauge

    Args:
        scenario: Name or type of scenario being analyzed

    Example:
        @track_analysis(scenario="apt_simulation")
        def analyze_telemetry(data):
            # Your analysis logic here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Increment active jobs
            current_analysis_jobs.inc()

            start_time = time.time()
            status = "success"

            try:
                result = func(*args, **kwargs)
                return result

            except Exception as e:
                status = "failure"
                errors_total.labels(
                    error_type=type(e).__name__,
                    component="analysis"
                ).inc()
                raise

            finally:
                # Record metrics
                duration = time.time() - start_time

                analysis_requests_total.labels(
                    scenario=scenario,
                    status=status
                ).inc()

                analysis_duration_seconds.labels(
                    scenario=scenario
                ).observe(duration)

                # Decrement active jobs
                current_analysis_jobs.dec()

                logger.info(
                    f"Analysis completed: scenario={scenario}, "
                    f"status={status}, duration={duration:.2f}s"
                )

        return wrapper
    return decorator


def track_session_analysis(func: Callable) -> Callable:
    """
    Decorator to track individual session analysis.

    Tracks:
    - Session analysis duration
    - Sessions detected (malicious vs benign)

    Example:
        @track_session_analysis
        def analyze_session(session):
            # Session analysis logic
            pass
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        start_time = time.time()

        try:
            result = func(*args, **kwargs)

            # Track session detection
            is_malicious = "true" if result.get("session_info", {}).get("risk_score", 0) > 0.5 else "false"
            sessions_detected_total.labels(is_malicious=is_malicious).inc()

            return result

        finally:
            duration = time.time() - start_time
            sessions_analysis_duration_seconds.observe(duration)

    return wrapper


def track_llm_request(agent: str, model: str = "unknown"):
    """
    Decorator to track LLM API requests.

    Args:
        agent: Name of the agent making the request
        model: LLM model being used

    Example:
        @track_llm_request(agent="narrative_generator", model="gpt-4")
        def generate_narrative(session):
            # LLM API call
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            status = "success"

            try:
                result = func(*args, **kwargs)

                # Track token usage if available in result
                if isinstance(result, dict) and "usage" in result:
                    usage = result["usage"]
                    if "prompt_tokens" in usage:
                        llm_tokens_used_total.labels(
                            agent=agent,
                            model=model,
                            token_type="prompt"
                        ).inc(usage["prompt_tokens"])
                    if "completion_tokens" in usage:
                        llm_tokens_used_total.labels(
                            agent=agent,
                            model=model,
                            token_type="completion"
                        ).inc(usage["completion_tokens"])

                return result

            except Exception as e:
                status = "failure"
                errors_total.labels(
                    error_type=type(e).__name__,
                    component="llm"
                ).inc()
                raise

            finally:
                duration = time.time() - start_time

                llm_requests_total.labels(
                    agent=agent,
                    model=model,
                    status=status
                ).inc()

                llm_request_duration_seconds.labels(
                    agent=agent,
                    model=model
                ).observe(duration)

        return wrapper
    return decorator


def track_database_query(operation: str, table: str):
    """
    Decorator to track database queries.

    Args:
        operation: Type of operation (select, insert, update, delete)
        table: Database table name

    Example:
        @track_database_query(operation="select", table="sessions")
        def get_session(session_id):
            # Database query
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            status = "success"

            try:
                result = func(*args, **kwargs)
                return result

            except Exception as e:
                status = "failure"
                errors_total.labels(
                    error_type=type(e).__name__,
                    component="database"
                ).inc()
                raise

            finally:
                duration = time.time() - start_time

                database_queries_total.labels(
                    operation=operation,
                    table=table,
                    status=status
                ).inc()

                database_query_duration_seconds.labels(
                    operation=operation,
                    table=table
                ).observe(duration)

        return wrapper
    return decorator


# ============================================================================
# Helper Functions
# ============================================================================

def record_event_processed(event_source: str = "unknown", count: int = 1):
    """
    Record that events have been processed.

    Args:
        event_source: Source of the events (upload, api, scenario)
        count: Number of events processed
    """
    events_processed_total.labels(event_source=event_source).inc(count)


def record_file_upload(file_size_bytes: int):
    """
    Record a file upload.

    Args:
        file_size_bytes: Size of uploaded file in bytes
    """
    file_upload_size_bytes.observe(file_size_bytes)


def record_ioc_extracted(ioc_type: str, count: int = 1):
    """
    Record IOC extraction.

    Args:
        ioc_type: Type of IOC (ip, domain, hash, etc.)
        count: Number of IOCs extracted
    """
    iocs_extracted_total.labels(ioc_type=ioc_type).inc(count)


def update_memory_usage(memory_type: str, bytes_used: int):
    """
    Update memory usage gauge.

    Args:
        memory_type: Type of memory (rss, vms, shared, etc.)
        bytes_used: Current memory usage in bytes
    """
    memory_usage_bytes.labels(type=memory_type).set(bytes_used)


def record_health_check(component: str, is_healthy: bool, duration_seconds: float):
    """
    Record health check results.

    Args:
        component: Component being checked
        is_healthy: Whether the component is healthy
        duration_seconds: Time taken for the health check
    """
    health_check_status.labels(component=component).set(1 if is_healthy else 0)
    health_check_duration_seconds.labels(component=component).observe(duration_seconds)


def get_metrics() -> bytes:
    """
    Get current metrics in Prometheus format.

    Returns:
        Metrics in Prometheus text format
    """
    return generate_latest()


def get_content_type() -> str:
    """
    Get the content type for Prometheus metrics.

    Returns:
        Content type string
    """
    return CONTENT_TYPE_LATEST


# ============================================================================
# Metrics Collection
# ============================================================================

def collect_system_metrics():
    """
    Collect system-level metrics (memory, CPU, etc.).

    Should be called periodically to update gauges.
    """
    try:
        import psutil
        process = psutil.Process()

        # Memory metrics
        mem_info = process.memory_info()
        update_memory_usage("rss", mem_info.rss)
        update_memory_usage("vms", mem_info.vms)

        # System-wide memory
        vm = psutil.virtual_memory()
        memory_usage_bytes.labels(type="system_total").set(vm.total)
        memory_usage_bytes.labels(type="system_available").set(vm.available)
        memory_usage_bytes.labels(type="system_used").set(vm.used)

    except ImportError:
        logger.warning("psutil not available, system metrics collection disabled")
    except Exception as e:
        logger.error(f"Error collecting system metrics: {e}")
