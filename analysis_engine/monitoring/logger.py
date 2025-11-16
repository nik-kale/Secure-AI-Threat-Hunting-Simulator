"""
Structured logging with JSON format, correlation IDs, and performance metrics.

Provides enhanced logging capabilities for the analysis engine with support for
structured data, request tracking, and automated performance metrics.
"""
from typing import Any, Dict, Optional
import logging
import json
import time
import uuid
from datetime import datetime
from functools import wraps
from contextvars import ContextVar
import sys
from pathlib import Path

# Context variable for correlation ID (thread-safe)
correlation_id_var: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)


class StructuredFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs in JSON format with additional context.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.

        Args:
            record: Log record to format

        Returns:
            JSON-formatted log string
        """
        # Base log structure
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation ID if available
        correlation_id = correlation_id_var.get()
        if correlation_id:
            log_data["correlation_id"] = correlation_id

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }

        # Add custom fields from extra
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)

        # Add performance metrics if present
        if hasattr(record, 'performance'):
            log_data["performance"] = record.performance

        # Add request context if present
        if hasattr(record, 'request_context'):
            log_data["request"] = record.request_context

        return json.dumps(log_data)


class StructuredLogger:
    """
    Enhanced logger with structured logging support.

    Provides methods for logging with additional context, performance metrics,
    and correlation tracking.
    """

    def __init__(self, name: str, level: int = logging.INFO):
        """
        Initialize structured logger.

        Args:
            name: Logger name
            level: Logging level
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()

        # Add JSON formatter to console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(StructuredFormatter())
        self.logger.addHandler(console_handler)

    def _log(
        self,
        level: int,
        message: str,
        extra_fields: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Internal logging method with structured data support.

        Args:
            level: Logging level
            message: Log message
            extra_fields: Additional fields to include in the log
            **kwargs: Additional keyword arguments for the logger
        """
        # Create extra dict for structured fields
        extra = kwargs.get('extra', {})
        if extra_fields:
            extra['extra_fields'] = extra_fields
            kwargs['extra'] = extra

        self.logger.log(level, message, **kwargs)

    def debug(self, message: str, **fields):
        """Log debug message with structured fields."""
        self._log(logging.DEBUG, message, extra_fields=fields)

    def info(self, message: str, **fields):
        """Log info message with structured fields."""
        self._log(logging.INFO, message, extra_fields=fields)

    def warning(self, message: str, **fields):
        """Log warning message with structured fields."""
        self._log(logging.WARNING, message, extra_fields=fields)

    def error(self, message: str, **fields):
        """Log error message with structured fields."""
        self._log(logging.ERROR, message, extra_fields=fields)

    def critical(self, message: str, **fields):
        """Log critical message with structured fields."""
        self._log(logging.CRITICAL, message, extra_fields=fields)

    def performance(
        self,
        message: str,
        duration: float,
        operation: str,
        **fields
    ):
        """
        Log performance metrics.

        Args:
            message: Log message
            duration: Operation duration in seconds
            operation: Name of the operation
            **fields: Additional fields
        """
        perf_data = {
            "operation": operation,
            "duration_seconds": round(duration, 4),
            "duration_ms": round(duration * 1000, 2)
        }

        extra = {
            'extra_fields': fields,
            'performance': perf_data
        }

        self.logger.info(message, extra=extra)

    def request(
        self,
        message: str,
        method: str,
        path: str,
        status_code: Optional[int] = None,
        duration: Optional[float] = None,
        **fields
    ):
        """
        Log HTTP request information.

        Args:
            message: Log message
            method: HTTP method
            path: Request path
            status_code: HTTP status code
            duration: Request duration in seconds
            **fields: Additional fields
        """
        request_data = {
            "method": method,
            "path": path,
        }

        if status_code is not None:
            request_data["status_code"] = status_code

        if duration is not None:
            request_data["duration_seconds"] = round(duration, 4)

        extra = {
            'extra_fields': fields,
            'request_context': request_data
        }

        self.logger.info(message, extra=extra)


# ============================================================================
# Global Logger Instances
# ============================================================================

# Create default loggers for different components
api_logger = StructuredLogger("api")
analysis_logger = StructuredLogger("analysis")
database_logger = StructuredLogger("database")
llm_logger = StructuredLogger("llm")
system_logger = StructuredLogger("system")


# ============================================================================
# Correlation ID Management
# ============================================================================

def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """
    Set correlation ID for the current context.

    Args:
        correlation_id: Correlation ID to set (generates new UUID if None)

    Returns:
        The correlation ID that was set
    """
    if correlation_id is None:
        correlation_id = str(uuid.uuid4())

    correlation_id_var.set(correlation_id)
    return correlation_id


def get_correlation_id() -> Optional[str]:
    """
    Get the current correlation ID.

    Returns:
        Current correlation ID or None
    """
    return correlation_id_var.get()


def clear_correlation_id():
    """Clear the correlation ID from the current context."""
    correlation_id_var.set(None)


# ============================================================================
# Decorators
# ============================================================================

def log_performance(logger: Optional[StructuredLogger] = None, operation: Optional[str] = None):
    """
    Decorator to automatically log performance metrics for a function.

    Args:
        logger: Logger to use (defaults to analysis_logger)
        operation: Operation name (defaults to function name)

    Example:
        @log_performance(operation="data_processing")
        def process_data(data):
            # Processing logic
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger_to_use = logger or analysis_logger
            operation_name = operation or func.__name__

            start_time = time.time()

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                logger_to_use.performance(
                    f"{operation_name} completed successfully",
                    duration=duration,
                    operation=operation_name,
                    status="success"
                )

                return result

            except Exception as e:
                duration = time.time() - start_time

                logger_to_use.performance(
                    f"{operation_name} failed: {str(e)}",
                    duration=duration,
                    operation=operation_name,
                    status="failure",
                    error_type=type(e).__name__
                )
                raise

        return wrapper
    return decorator


def with_correlation_id(func):
    """
    Decorator to automatically create and manage correlation IDs.

    Creates a new correlation ID for each function call and clears it afterwards.

    Example:
        @with_correlation_id
        def handle_request(data):
            # All logs within this function will have the same correlation_id
            logger.info("Processing request")
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Generate new correlation ID
        correlation_id = set_correlation_id()

        try:
            result = func(*args, **kwargs)
            return result
        finally:
            # Clear correlation ID after function completes
            clear_correlation_id()

    return wrapper


def log_function_call(
    logger: Optional[StructuredLogger] = None,
    log_args: bool = False,
    log_result: bool = False
):
    """
    Decorator to log function calls with optional argument and result logging.

    Args:
        logger: Logger to use (defaults to analysis_logger)
        log_args: Whether to log function arguments
        log_result: Whether to log function result

    Example:
        @log_function_call(log_args=True)
        def process_event(event_id, event_data):
            # Processing logic
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger_to_use = logger or analysis_logger

            fields = {
                "function": func.__name__,
                "module": func.__module__
            }

            if log_args and args:
                fields["args"] = str(args)
            if log_args and kwargs:
                fields["kwargs"] = str(kwargs)

            logger_to_use.info(f"Calling {func.__name__}", **fields)

            try:
                result = func(*args, **kwargs)

                if log_result:
                    logger_to_use.info(
                        f"{func.__name__} completed",
                        function=func.__name__,
                        result=str(result)[:200]  # Limit result length
                    )

                return result

            except Exception as e:
                logger_to_use.error(
                    f"{func.__name__} failed",
                    function=func.__name__,
                    error=str(e),
                    error_type=type(e).__name__
                )
                raise

        return wrapper
    return decorator


# ============================================================================
# File Logging Setup
# ============================================================================

def setup_file_logging(
    log_dir: Path,
    log_file: str = "analysis_engine.log",
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5
):
    """
    Setup file-based logging with rotation.

    Args:
        log_dir: Directory for log files
        log_file: Log file name
        max_bytes: Maximum file size before rotation
        backup_count: Number of backup files to keep
    """
    from logging.handlers import RotatingFileHandler

    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / log_file

    # Create rotating file handler
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setFormatter(StructuredFormatter())

    # Add to all our structured loggers
    for logger in [api_logger, analysis_logger, database_logger, llm_logger, system_logger]:
        logger.logger.addHandler(file_handler)

    system_logger.info(
        "File logging configured",
        log_path=str(log_path),
        max_bytes=max_bytes,
        backup_count=backup_count
    )


# ============================================================================
# Request Context Manager
# ============================================================================

class RequestContext:
    """
    Context manager for tracking request lifecycle.

    Automatically manages correlation IDs and logs request start/end.
    """

    def __init__(
        self,
        operation: str,
        logger: Optional[StructuredLogger] = None,
        **context_fields
    ):
        """
        Initialize request context.

        Args:
            operation: Name of the operation
            logger: Logger to use
            **context_fields: Additional context fields
        """
        self.operation = operation
        self.logger = logger or api_logger
        self.context_fields = context_fields
        self.correlation_id: Optional[str] = None
        self.start_time: Optional[float] = None

    def __enter__(self):
        """Enter request context."""
        self.correlation_id = set_correlation_id()
        self.start_time = time.time()

        self.logger.info(
            f"Starting {self.operation}",
            operation=self.operation,
            **self.context_fields
        )

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit request context."""
        duration = time.time() - self.start_time

        if exc_type is None:
            self.logger.performance(
                f"{self.operation} completed",
                duration=duration,
                operation=self.operation,
                status="success",
                **self.context_fields
            )
        else:
            self.logger.error(
                f"{self.operation} failed",
                operation=self.operation,
                duration=duration,
                error_type=exc_type.__name__,
                error=str(exc_val),
                **self.context_fields
            )

        clear_correlation_id()
        return False  # Don't suppress exceptions
