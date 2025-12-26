"""
Centralized configuration management using Pydantic settings.
"""
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from typing import List, Optional
import os


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # ===== API Configuration =====
    api_host: str = Field("0.0.0.0", env="ANALYSIS_API_HOST")
    api_port: int = Field(8000, env="ANALYSIS_API_PORT")
    api_debug: bool = Field(False, env="ANALYSIS_API_DEBUG")
    api_workers: int = Field(1, env="API_WORKERS")

    # ===== CORS & Security =====
    allowed_origins: str = Field(
        "http://localhost:3000",
        env="ALLOWED_ORIGINS",
        description="Comma-separated list of allowed origins"
    )
    api_key: Optional[str] = Field(None, env="API_KEY")
    admin_api_key: Optional[str] = Field(None, env="ADMIN_API_KEY")
    max_upload_size_mb: int = Field(100, env="MAX_UPLOAD_SIZE_MB")
    max_events_per_request: int = Field(10000, env="MAX_EVENTS_PER_REQUEST")

    @field_validator("allowed_origins")
    @classmethod
    def parse_origins(cls, v):
        """Parse comma-separated origins into list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    # ===== Analysis Configuration =====
    correlation_time_window_minutes: int = Field(60, env="CORRELATION_TIME_WINDOW_MINUTES")
    min_events_for_alert: int = Field(3, env="MIN_EVENTS_FOR_ALERT")
    risk_score_threshold: float = Field(0.5, env="RISK_SCORE_THRESHOLD")

    # ===== Generator Configuration =====
    default_account_id: str = Field("123456789012", env="DEFAULT_ACCOUNT_ID")
    default_region: str = Field("us-east-1", env="DEFAULT_REGION")
    default_tenant_id: str = Field("synthetic-tenant-001", env="DEFAULT_TENANT_ID")
    scenario_duration_hours: float = Field(2.0, env="SCENARIO_DURATION_HOURS")
    event_noise_ratio: float = Field(0.3, env="EVENT_NOISE_RATIO")

    # ===== Output Paths =====
    output_dir: str = Field("./output", env="OUTPUT_DIR")
    telemetry_dir: str = Field("./output/telemetry", env="TELEMETRY_DIR")
    reports_dir: str = Field("./output/reports", env="REPORTS_DIR")
    scenarios_dir: str = Field("./output/scenarios", env="SCENARIOS_DIR")

    # ===== Logging =====
    log_level: str = Field("INFO", env="LOG_LEVEL")
    log_format: str = Field("json", env="LOG_FORMAT")
    log_file: Optional[str] = Field(None, env="LOG_FILE")

    # ===== Database =====
    db_connection_string: str = Field(
        "sqlite:///./data/threat_hunting.db",
        env="DB_CONNECTION_STRING"
    )
    db_pool_size: int = Field(5, env="DB_POOL_SIZE")
    db_max_overflow: int = Field(10, env="DB_MAX_OVERFLOW")
    db_echo: bool = Field(False, env="DB_ECHO")

    # ===== LLM Integration =====
    llm_provider: str = Field("none", env="LLM_PROVIDER")
    llm_model: Optional[str] = Field(None, env="LLM_MODEL")
    openai_api_key: Optional[str] = Field(None, env="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(None, env="ANTHROPIC_API_KEY")
    llm_temperature: float = Field(0.3, env="LLM_TEMPERATURE")
    llm_max_tokens: int = Field(2000, env="LLM_MAX_TOKENS")

    # ===== Threat Intelligence =====
    enable_threat_intel: bool = Field(False, env="ENABLE_THREAT_INTEL")
    abuseipdb_api_key: Optional[str] = Field(None, env="ABUSEIPDB_API_KEY")
    virustotal_api_key: Optional[str] = Field(None, env="VIRUSTOTAL_API_KEY")
    threat_intel_cache_ttl: int = Field(3600, env="THREAT_INTEL_CACHE_TTL")

    # ===== Performance & Monitoring =====
    enable_metrics: bool = Field(False, env="ENABLE_METRICS")
    metrics_port: int = Field(9090, env="METRICS_PORT")
    sentry_dsn: Optional[str] = Field(None, env="SENTRY_DSN")
    enable_profiling: bool = Field(False, env="ENABLE_PROFILING")
    
    # ===== OpenTelemetry Tracing =====
    otel_enabled: bool = Field(False, env="OTEL_ENABLED")
    otel_service_name: str = Field("threat-hunting-simulator", env="OTEL_SERVICE_NAME")
    otel_service_version: str = Field("3.0.0", env="OTEL_SERVICE_VERSION")
    otel_exporter_type: str = Field("console", env="OTEL_EXPORTER_TYPE")
    otel_exporter_endpoint: Optional[str] = Field(None, env="OTEL_EXPORTER_ENDPOINT")
    otel_console_exporter: bool = Field(False, env="OTEL_CONSOLE_EXPORTER")

    # ===== Streaming & Performance =====
    streaming_chunk_size: int = Field(1000, env="STREAMING_CHUNK_SIZE")
    max_concurrent_analyses: int = Field(5, env="MAX_CONCURRENT_ANALYSES")

    # ===== Redis Caching =====
    redis_enabled: bool = Field(False, env="REDIS_ENABLED")
    redis_host: str = Field("localhost", env="REDIS_HOST")
    redis_port: int = Field(6379, env="REDIS_PORT")
    redis_db: int = Field(0, env="REDIS_DB")
    redis_password: Optional[str] = Field(None, env="REDIS_PASSWORD")
    redis_cache_ttl: int = Field(3600, env="REDIS_CACHE_TTL")
    redis_max_connections: int = Field(50, env="REDIS_MAX_CONNECTIONS")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings."""
    return settings


def reload_settings():
    """Reload settings from environment."""
    global settings
    settings = Settings()
    return settings
