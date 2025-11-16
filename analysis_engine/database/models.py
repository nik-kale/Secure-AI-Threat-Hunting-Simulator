"""
SQLAlchemy models for AI Threat Hunting Simulator database.

This module defines the database schema for persisting threat hunting
analysis results, detected sessions, IOCs, and threat intelligence data.
"""
from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSON, JSONB


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


class AnalysisRun(Base):
    """
    Represents a complete analysis run on a telemetry dataset.

    Each analysis run processes a scenario and generates threat hunting results.
    """
    __tablename__ = "analysis_runs"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Analysis metadata
    scenario_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True
    )

    # Analysis scope
    num_events: Mapped[int] = mapped_column(Integer, nullable=False)
    num_sessions: Mapped[int] = mapped_column(Integer, nullable=False)
    num_suspicious_sessions: Mapped[int] = mapped_column(Integer, default=0)

    # Configuration parameters
    time_window_minutes: Mapped[int] = mapped_column(Integer, default=60)
    min_events_for_session: Mapped[int] = mapped_column(Integer, default=3)
    risk_threshold: Mapped[float] = mapped_column(Float, default=0.5)

    # Complete results stored as JSON
    results: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Analysis metadata
    telemetry_file_path: Mapped[Optional[str]] = mapped_column(String(512))
    analysis_duration_seconds: Mapped[Optional[float]] = mapped_column(Float)

    # Relationships
    detected_sessions: Mapped[List["DetectedSession"]] = relationship(
        "DetectedSession",
        back_populates="analysis_run",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<AnalysisRun(id={self.id}, scenario='{self.scenario_name}', "
            f"sessions={self.num_sessions}, created_at={self.created_at})>"
        )


class DetectedSession(Base):
    """
    Represents a correlated session detected during threat hunting analysis.

    Each session contains multiple correlated events that may indicate
    malicious activity.
    """
    __tablename__ = "detected_sessions"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Foreign key to analysis run
    analysis_run_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Session identification
    session_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Risk assessment
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # Session metadata
    num_events: Mapped[int] = mapped_column(Integer, nullable=False)
    start_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float)

    # Attack analysis
    kill_chain_stages: Mapped[list] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)

    # Session entities
    principals: Mapped[list] = mapped_column(JSON, default=list)
    source_ips: Mapped[list] = mapped_column(JSON, default=list)
    resources: Mapped[list] = mapped_column(JSON, default=list)
    event_types: Mapped[list] = mapped_column(JSON, default=list)

    # Analysis results
    iocs: Mapped[dict] = mapped_column(JSON, default=dict)
    narrative: Mapped[Optional[str]] = mapped_column(Text)
    response_plan: Mapped[Optional[dict]] = mapped_column(JSON)

    # Full session data
    session_data: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Relationships
    analysis_run: Mapped["AnalysisRun"] = relationship(
        "AnalysisRun",
        back_populates="detected_sessions"
    )
    ioc_records: Mapped[List["IOC"]] = relationship(
        "IOC",
        back_populates="session",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<DetectedSession(id={self.id}, session_id='{self.session_id}', "
            f"risk_score={self.risk_score:.2f}, malicious={self.is_malicious})>"
        )


class IOC(Base):
    """
    Indicator of Compromise extracted from detected sessions.

    IOCs include IP addresses, domains, file hashes, and other artifacts
    that may indicate malicious activity.
    """
    __tablename__ = "iocs"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Foreign key to detected session
    session_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("detected_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # IOC classification
    ioc_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True
    )  # ip, domain, url, hash, email, etc.

    # IOC data
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(20),
        default="medium"
    )  # low, medium, high, critical

    # Temporal metadata
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now()
    )

    # Context and metadata
    context: Mapped[Optional[str]] = mapped_column(Text)
    metadata: Mapped[dict] = mapped_column(JSON, default=dict)

    # Enrichment flag
    enriched: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    session: Mapped["DetectedSession"] = relationship(
        "DetectedSession",
        back_populates="ioc_records"
    )
    threat_intel: Mapped[List["ThreatIntelligence"]] = relationship(
        "ThreatIntelligence",
        back_populates="ioc",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<IOC(id={self.id}, type='{self.ioc_type}', "
            f"value='{self.value}', severity='{self.severity}')>"
        )


class ThreatIntelligence(Base):
    """
    Threat intelligence data enriching IOCs.

    Contains external threat intelligence lookups for IOCs from various
    providers (VirusTotal, AbuseIPDB, etc.).
    """
    __tablename__ = "threat_intelligence"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Foreign key to IOC
    ioc_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("iocs.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Intelligence provider
    provider: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True
    )  # virustotal, abuseipdb, shodan, etc.

    # Threat assessment
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    reputation_score: Mapped[Optional[float]] = mapped_column(Float)
    confidence: Mapped[Optional[float]] = mapped_column(Float)

    # Classification
    threat_types: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)

    # Provider-specific data
    raw_response: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Temporal metadata
    last_checked: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True
    )

    # Additional metadata
    notes: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    ioc: Mapped["IOC"] = relationship(
        "IOC",
        back_populates="threat_intel"
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatIntelligence(id={self.id}, provider='{self.provider}', "
            f"malicious={self.is_malicious}, score={self.reputation_score})>"
        )
