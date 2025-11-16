"""
Performance monitoring and observability package.

Provides comprehensive monitoring capabilities including:
- Prometheus metrics for monitoring and alerting
- Performance profiling for optimization
- Structured logging with correlation IDs
"""

from .metrics import (
    # Decorators
    track_analysis,
    track_session_analysis,
    track_llm_request,
    track_database_query,

    # Helper functions
    record_event_processed,
    record_file_upload,
    record_ioc_extracted,
    update_memory_usage,
    record_health_check,
    get_metrics,
    get_content_type,
    collect_system_metrics,

    # Metrics
    analysis_requests_total,
    analysis_duration_seconds,
    events_processed_total,
    sessions_detected_total,
    current_analysis_jobs,
    http_requests_total,
    http_request_duration_seconds,
    errors_total,
    health_check_status,
)

from .profiler import (
    Profiler,
    profile,
    timed,
    ProfileReport,
    TimingEntry,
    MemorySnapshot,
)

from .logger import (
    StructuredLogger,
    StructuredFormatter,
    set_correlation_id,
    get_correlation_id,
    clear_correlation_id,
    log_performance,
    with_correlation_id,
    log_function_call,
    setup_file_logging,
    RequestContext,

    # Logger instances
    api_logger,
    analysis_logger,
    database_logger,
    llm_logger,
    system_logger,
)

__all__ = [
    # Metrics
    "track_analysis",
    "track_session_analysis",
    "track_llm_request",
    "track_database_query",
    "record_event_processed",
    "record_file_upload",
    "record_ioc_extracted",
    "update_memory_usage",
    "record_health_check",
    "get_metrics",
    "get_content_type",
    "collect_system_metrics",
    "analysis_requests_total",
    "analysis_duration_seconds",
    "events_processed_total",
    "sessions_detected_total",
    "current_analysis_jobs",
    "http_requests_total",
    "http_request_duration_seconds",
    "errors_total",
    "health_check_status",

    # Profiler
    "Profiler",
    "profile",
    "timed",
    "ProfileReport",
    "TimingEntry",
    "MemorySnapshot",

    # Logger
    "StructuredLogger",
    "StructuredFormatter",
    "set_correlation_id",
    "get_correlation_id",
    "clear_correlation_id",
    "log_performance",
    "with_correlation_id",
    "log_function_call",
    "setup_file_logging",
    "RequestContext",
    "api_logger",
    "analysis_logger",
    "database_logger",
    "llm_logger",
    "system_logger",
]
