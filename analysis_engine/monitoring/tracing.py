"""
OpenTelemetry distributed tracing integration.
"""
import os
import logging
from typing import Optional
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

# OTLP exporters
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as GRPCExporter
    OTLP_GRPC_AVAILABLE = True
except ImportError:
    OTLP_GRPC_AVAILABLE = False

try:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as HTTPExporter
    OTLP_HTTP_AVAILABLE = True
except ImportError:
    OTLP_HTTP_AVAILABLE = False

# Jaeger exporter
try:
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    JAEGER_AVAILABLE = True
except ImportError:
    JAEGER_AVAILABLE = False


logger = logging.getLogger(__name__)


class TracingManager:
    """Manages OpenTelemetry tracing configuration."""
    
    def __init__(
        self,
        service_name: str = "threat-hunting-simulator",
        service_version: str = "3.0.0",
        exporter_type: Optional[str] = None,
        exporter_endpoint: Optional[str] = None,
        enable_console: bool = False
    ):
        """
        Initialize tracing manager.
        
        Args:
            service_name: Name of the service
            service_version: Version of the service
            exporter_type: Type of exporter (otlp_grpc, otlp_http, jaeger, console)
            exporter_endpoint: Endpoint URL for exporter
            enable_console: Also export to console for debugging
        """
        self.service_name = service_name
        self.service_version = service_version
        self.exporter_type = exporter_type or os.getenv("OTEL_EXPORTER_TYPE", "console")
        self.exporter_endpoint = exporter_endpoint or os.getenv("OTEL_EXPORTER_ENDPOINT")
        self.enable_console = enable_console or os.getenv("OTEL_CONSOLE_EXPORTER", "false").lower() == "true"
        
        self.tracer_provider: Optional[TracerProvider] = None
        self.tracer: Optional[trace.Tracer] = None
        self.is_initialized = False

    def init_tracing(self) -> trace.Tracer:
        """
        Initialize OpenTelemetry tracing.
        
        Returns:
            Configured tracer instance
        """
        if self.is_initialized:
            logger.warning("Tracing already initialized")
            return self.tracer
        
        # Create resource with service information
        resource = Resource.create({
            SERVICE_NAME: self.service_name,
            SERVICE_VERSION: self.service_version,
            "deployment.environment": os.getenv("ENVIRONMENT", "development"),
        })
        
        # Create tracer provider
        self.tracer_provider = TracerProvider(resource=resource)
        
        # Add exporters
        self._configure_exporters()
        
        # Set global tracer provider
        trace.set_tracer_provider(self.tracer_provider)
        
        # Get tracer
        self.tracer = trace.get_tracer(__name__)
        
        self.is_initialized = True
        logger.info(f"OpenTelemetry tracing initialized with {self.exporter_type} exporter")
        
        return self.tracer

    def _configure_exporters(self):
        """Configure and add span exporters."""
        exporters = []
        
        # Console exporter (for debugging)
        if self.enable_console:
            exporters.append(ConsoleSpanExporter())
            logger.info("Console span exporter enabled")
        
        # OTLP gRPC exporter
        if self.exporter_type == "otlp_grpc":
            if not OTLP_GRPC_AVAILABLE:
                logger.error("OTLP gRPC exporter not available. Install: pip install opentelemetry-exporter-otlp-proto-grpc")
            elif not self.exporter_endpoint:
                logger.error("OTLP gRPC exporter requires OTEL_EXPORTER_ENDPOINT")
            else:
                exporters.append(GRPCExporter(endpoint=self.exporter_endpoint))
                logger.info(f"OTLP gRPC exporter configured: {self.exporter_endpoint}")
        
        # OTLP HTTP exporter
        elif self.exporter_type == "otlp_http":
            if not OTLP_HTTP_AVAILABLE:
                logger.error("OTLP HTTP exporter not available. Install: pip install opentelemetry-exporter-otlp-proto-http")
            elif not self.exporter_endpoint:
                logger.error("OTLP HTTP exporter requires OTEL_EXPORTER_ENDPOINT")
            else:
                exporters.append(HTTPExporter(endpoint=self.exporter_endpoint))
                logger.info(f"OTLP HTTP exporter configured: {self.exporter_endpoint}")
        
        # Jaeger exporter
        elif self.exporter_type == "jaeger":
            if not JAEGER_AVAILABLE:
                logger.error("Jaeger exporter not available. Install: pip install opentelemetry-exporter-jaeger")
            else:
                # Jaeger defaults
                agent_host = os.getenv("JAEGER_AGENT_HOST", "localhost")
                agent_port = int(os.getenv("JAEGER_AGENT_PORT", "6831"))
                
                exporters.append(
                    JaegerExporter(
                        agent_host_name=agent_host,
                        agent_port=agent_port
                    )
                )
                logger.info(f"Jaeger exporter configured: {agent_host}:{agent_port}")
        
        # Console exporter (fallback)
        elif self.exporter_type == "console":
            exporters.append(ConsoleSpanExporter())
            logger.info("Console span exporter configured")
        
        else:
            logger.warning(f"Unknown exporter type: {self.exporter_type}, falling back to console")
            exporters.append(ConsoleSpanExporter())
        
        # Add all exporters with batch processor
        for exporter in exporters:
            self.tracer_provider.add_span_processor(
                BatchSpanProcessor(exporter)
            )

    def instrument_fastapi(self, app):
        """
        Instrument FastAPI application.
        
        Args:
            app: FastAPI application instance
        """
        if not self.is_initialized:
            logger.warning("Tracing not initialized, initializing now")
            self.init_tracing()
        
        FastAPIInstrumentor.instrument_app(app)
        logger.info("FastAPI instrumented for tracing")

    def instrument_httpx(self):
        """Instrument HTTPX client for outgoing requests."""
        if not self.is_initialized:
            logger.warning("Tracing not initialized, initializing now")
            self.init_tracing()
        
        HTTPXClientInstrumentor().instrument()
        logger.info("HTTPX client instrumented for tracing")

    def instrument_redis(self):
        """Instrument Redis client."""
        if not self.is_initialized:
            logger.warning("Tracing not initialized, initializing now")
            self.init_tracing()
        
        RedisInstrumentor().instrument()
        logger.info("Redis client instrumented for tracing")

    def instrument_sqlalchemy(self, engine=None):
        """
        Instrument SQLAlchemy for database tracing.
        
        Args:
            engine: Optional SQLAlchemy engine instance
        """
        if not self.is_initialized:
            logger.warning("Tracing not initialized, initializing now")
            self.init_tracing()
        
        if engine:
            SQLAlchemyInstrumentor().instrument(engine=engine)
        else:
            SQLAlchemyInstrumentor().instrument()
        
        logger.info("SQLAlchemy instrumented for tracing")

    @contextmanager
    def trace_operation(self, operation_name: str, attributes: Optional[dict] = None):
        """
        Context manager for tracing custom operations.
        
        Args:
            operation_name: Name of the operation
            attributes: Optional attributes to add to the span
            
        Example:
            with tracing_manager.trace_operation("load_events", {"file": "data.jsonl"}):
                events = load_events_from_file("data.jsonl")
        """
        if not self.is_initialized:
            # If tracing not initialized, just execute without tracing
            yield
            return
        
        with self.tracer.start_as_current_span(operation_name) as span:
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, str(value))
            
            try:
                yield span
            except Exception as e:
                span.set_attribute("error", True)
                span.set_attribute("error.message", str(e))
                span.set_attribute("error.type", type(e).__name__)
                raise

    def add_span_attributes(self, **attributes):
        """
        Add attributes to the current span.
        
        Args:
            **attributes: Attributes to add to current span
        """
        if not self.is_initialized:
            return
        
        current_span = trace.get_current_span()
        if current_span:
            for key, value in attributes.items():
                current_span.set_attribute(key, str(value))

    def shutdown(self):
        """Shutdown tracing and flush any pending spans."""
        if self.tracer_provider:
            self.tracer_provider.shutdown()
            logger.info("Tracing shutdown complete")


# Global tracing manager instance
_tracing_manager: Optional[TracingManager] = None


def init_tracing(
    service_name: str = "threat-hunting-simulator",
    service_version: str = "3.0.0",
    **kwargs
) -> TracingManager:
    """
    Initialize global tracing manager.
    
    Args:
        service_name: Name of the service
        service_version: Version of the service
        **kwargs: Additional arguments for TracingManager
        
    Returns:
        Configured tracing manager
    """
    global _tracing_manager
    
    if _tracing_manager is None:
        _tracing_manager = TracingManager(
            service_name=service_name,
            service_version=service_version,
            **kwargs
        )
        _tracing_manager.init_tracing()
    
    return _tracing_manager


def get_tracing_manager() -> Optional[TracingManager]:
    """Get the global tracing manager instance."""
    return _tracing_manager


def get_tracer() -> trace.Tracer:
    """Get the global tracer instance."""
    if _tracing_manager and _tracing_manager.tracer:
        return _tracing_manager.tracer
    return trace.get_tracer(__name__)

