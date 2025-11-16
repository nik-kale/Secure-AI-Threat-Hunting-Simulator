"""
Pydantic models for API request/response validation.

Provides type safety, validation, and automatic OpenAPI documentation.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field, validator, constr, conint, confloat
from enum import Enum


# ===== Enums =====

class ScenarioName(str, Enum):
    """Valid attack scenario names."""
    IAM_PRIV_ESCALATION = "iam_priv_escalation"
    CONTAINER_ESCAPE = "container_escape"
    CRED_STUFFING = "cred_stuffing"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    SUPPLY_CHAIN = "supply_chain"


class AnalysisStatus(str, Enum):
    """Analysis job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportFormat(str, Enum):
    """Report output format."""
    JSON = "json"
    MARKDOWN = "markdown"
    BOTH = "both"


# ===== Request Models =====

class GenerateScenarioRequest(BaseModel):
    """Request to generate a scenario."""
    account_id: Optional[constr(pattern=r'^\d{12}$')] = Field(
        None,
        description="AWS account ID (12 digits)",
        example="123456789012"
    )
    region: Optional[str] = Field(
        None,
        description="AWS region",
        example="us-east-1"
    )
    add_noise: bool = Field(
        True,
        description="Add benign background events"
    )
    duration_hours: Optional[confloat(gt=0, le=24)] = Field(
        None,
        description="Scenario duration in hours (max 24)",
        example=2.0
    )


class AnalyzeDataRequest(BaseModel):
    """Request to analyze telemetry data."""
    events: List[Dict[str, Any]] = Field(
        ...,
        description="List of telemetry events to analyze",
        min_items=1,
        max_items=10000
    )
    time_window_minutes: Optional[conint(gt=0, le=1440)] = Field(
        60,
        description="Correlation time window in minutes"
    )

    @validator('events')
    def validate_events(cls, v):
        """Validate events have required fields."""
        if len(v) > 10000:
            raise ValueError("Maximum 10,000 events per request")
        return v


# ===== Response Models =====

class HealthStatus(str, Enum):
    """Health check status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ComponentHealth(BaseModel):
    """Individual component health status."""
    status: HealthStatus
    message: Optional[str] = None
    latency_ms: Optional[float] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: HealthStatus
    timestamp: datetime
    version: str
    components: Dict[str, ComponentHealth]

    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2025-11-16T12:34:56Z",
                "version": "3.0.0",
                "components": {
                    "database": {
                        "status": "healthy",
                        "latency_ms": 5.2
                    },
                    "api": {
                        "status": "healthy"
                    }
                }
            }
        }


class IOCs(BaseModel):
    """Indicators of Compromise."""
    ip_addresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    api_keys: List[str] = Field(default_factory=list)
    user_agents: List[str] = Field(default_factory=list)
    principals: List[str] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=list)
    command_lines: List[str] = Field(default_factory=list)


class ResponseAction(BaseModel):
    """Incident response action."""
    priority: str = Field(..., description="Action priority (CRITICAL, HIGH, MEDIUM, LOW)")
    action: str = Field(..., description="Action to take")
    details: Optional[str] = Field(None, description="Additional details")


class ResponsePlan(BaseModel):
    """Incident response plan."""
    immediate_actions: List[ResponseAction] = Field(default_factory=list)
    containment: List[str] = Field(default_factory=list)
    eradication: List[str] = Field(default_factory=list)
    recovery: List[str] = Field(default_factory=list)
    lessons_learned: List[str] = Field(default_factory=list)


class Session(BaseModel):
    """Analysis session with threat details."""
    session_id: str
    principal: str
    risk_score: confloat(ge=0, le=1)
    event_count: conint(ge=0)
    start_time: str
    end_time: str
    mitre_techniques: List[str] = Field(default_factory=list)
    kill_chain_stages: List[str] = Field(default_factory=list)
    iocs: IOCs
    narrative: str
    response_plan: ResponsePlan

    class Config:
        schema_extra = {
            "example": {
                "session_id": "sess_abc123",
                "principal": "arn:aws:iam::123456789012:user/attacker",
                "risk_score": 0.87,
                "event_count": 31,
                "start_time": "2025-11-16T10:00:00Z",
                "end_time": "2025-11-16T10:47:00Z",
                "mitre_techniques": ["T1078.004", "T1548.005", "T1136.003"],
                "kill_chain_stages": ["reconnaissance", "privilege_escalation", "persistence"],
                "iocs": {
                    "ip_addresses": ["203.0.113.42"],
                    "principals": ["arn:aws:iam::123456789012:user/attacker"]
                },
                "narrative": "An attacker leveraged compromised credentials...",
                "response_plan": {
                    "immediate_actions": [
                        {
                            "priority": "CRITICAL",
                            "action": "Revoke compromised credentials",
                            "details": "User: attacker"
                        }
                    ]
                }
            }
        }


class AnalysisResult(BaseModel):
    """Analysis results from pipeline."""
    total_events: conint(ge=0)
    total_sessions: conint(ge=0)
    suspicious_sessions: conint(ge=0)
    sessions: List[Session]
    analysis_duration_seconds: Optional[float] = None

    class Config:
        schema_extra = {
            "example": {
                "total_events": 105,
                "total_sessions": 3,
                "suspicious_sessions": 1,
                "sessions": [],
                "analysis_duration_seconds": 2.5
            }
        }


class GenerateScenarioResponse(BaseModel):
    """Response from scenario generation."""
    status: str = Field(..., description="Generation status")
    scenario_name: ScenarioName
    output_dir: str
    telemetry_file: str
    event_count: conint(ge=0)
    generation_duration_seconds: Optional[float] = None

    class Config:
        schema_extra = {
            "example": {
                "status": "success",
                "scenario_name": "iam_priv_escalation",
                "output_dir": "./output/iam_priv_escalation",
                "telemetry_file": "./output/iam_priv_escalation/telemetry.jsonl",
                "event_count": 31,
                "generation_duration_seconds": 0.8
            }
        }


class ScenarioInfo(BaseModel):
    """Scenario metadata."""
    name: ScenarioName
    display_name: str
    description: str
    mitre_techniques: List[str]
    duration_hours: float
    typical_event_count: conint(ge=0)
    difficulty: str = Field(..., description="Difficulty level: easy, medium, hard")


class ScenarioListResponse(BaseModel):
    """List of available scenarios."""
    scenarios: List[ScenarioInfo]
    total_count: conint(ge=0)

    class Config:
        schema_extra = {
            "example": {
                "scenarios": [
                    {
                        "name": "iam_priv_escalation",
                        "display_name": "IAM Privilege Escalation",
                        "description": "PassRole exploitation via Lambda",
                        "mitre_techniques": ["T1078.004", "T1548.005"],
                        "duration_hours": 1.0,
                        "typical_event_count": 31,
                        "difficulty": "medium"
                    }
                ],
                "total_count": 6
            }
        }


class ErrorDetail(BaseModel):
    """Error detail information."""
    field: Optional[str] = None
    message: str
    type: Optional[str] = None


class ErrorResponse(BaseModel):
    """Error response."""
    error: str
    detail: Optional[str] = None
    errors: Optional[List[ErrorDetail]] = None
    request_id: Optional[str] = None
    timestamp: datetime

    class Config:
        schema_extra = {
            "example": {
                "error": "Validation Error",
                "detail": "Invalid input parameters",
                "errors": [
                    {
                        "field": "events",
                        "message": "Maximum 10,000 events per request",
                        "type": "value_error"
                    }
                ],
                "request_id": "req_xyz789",
                "timestamp": "2025-11-16T12:34:56Z"
            }
        }


class DatabaseAnalysis(BaseModel):
    """Database-stored analysis record."""
    run_id: int
    run_name: Optional[str]
    telemetry_file: str
    total_events: conint(ge=0)
    total_sessions: conint(ge=0)
    suspicious_sessions: conint(ge=0)
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[float]
    status: AnalysisStatus


class DatabaseAnalysisListResponse(BaseModel):
    """List of database analyses."""
    analyses: List[DatabaseAnalysis]
    total_count: conint(ge=0)
    page: conint(ge=1)
    page_size: conint(ge=1, le=100)


class StatsResponse(BaseModel):
    """API statistics."""
    timestamp: float
    version: str
    metrics: Dict[str, Any]
    summary: Dict[str, Any]


# ===== File Upload Models =====

class FileUploadResponse(BaseModel):
    """File upload response."""
    filename: str
    size_bytes: conint(ge=0)
    content_type: str
    uploaded_at: datetime
    analysis_started: bool

    class Config:
        schema_extra = {
            "example": {
                "filename": "telemetry.jsonl",
                "size_bytes": 1048576,
                "content_type": "application/x-ndjson",
                "uploaded_at": "2025-11-16T12:34:56Z",
                "analysis_started": True
            }
        }
