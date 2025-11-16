"""
Data access layer for AI Threat Hunting Simulator.

This module provides repository classes for accessing and manipulating
threat hunting data in the database.
"""
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from .models import AnalysisRun, DetectedSession, IOC, ThreatIntelligence

logger = logging.getLogger(__name__)


class AnalysisRepository:
    """Repository for managing AnalysisRun records."""

    def __init__(self, session: Session):
        """
        Initialize repository with database session.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save_analysis_run(
        self,
        scenario_name: str,
        num_events: int,
        num_sessions: int,
        results: Dict[str, Any],
        num_suspicious_sessions: int = 0,
        time_window_minutes: int = 60,
        min_events_for_session: int = 3,
        risk_threshold: float = 0.5,
        telemetry_file_path: Optional[str] = None,
        analysis_duration_seconds: Optional[float] = None,
    ) -> AnalysisRun:
        """
        Save a new analysis run to the database.

        Args:
            scenario_name: Name of the analyzed scenario
            num_events: Total number of events analyzed
            num_sessions: Total number of sessions detected
            results: Complete analysis results as dictionary
            num_suspicious_sessions: Number of suspicious sessions detected
            time_window_minutes: Time window used for correlation
            min_events_for_session: Minimum events required for session
            risk_threshold: Risk score threshold used
            telemetry_file_path: Path to telemetry file
            analysis_duration_seconds: Duration of analysis

        Returns:
            Created AnalysisRun instance
        """
        analysis_run = AnalysisRun(
            scenario_name=scenario_name,
            num_events=num_events,
            num_sessions=num_sessions,
            num_suspicious_sessions=num_suspicious_sessions,
            results=results,
            time_window_minutes=time_window_minutes,
            min_events_for_session=min_events_for_session,
            risk_threshold=risk_threshold,
            telemetry_file_path=telemetry_file_path,
            analysis_duration_seconds=analysis_duration_seconds,
        )

        self.session.add(analysis_run)
        self.session.flush()  # Flush to get the ID

        logger.info(
            f"Saved analysis run {analysis_run.id} for scenario '{scenario_name}'"
        )
        return analysis_run

    def get_analysis_run(
        self,
        run_id: int,
        include_sessions: bool = False
    ) -> Optional[AnalysisRun]:
        """
        Retrieve an analysis run by ID.

        Args:
            run_id: Analysis run ID
            include_sessions: Whether to eagerly load detected sessions

        Returns:
            AnalysisRun instance or None if not found
        """
        query = select(AnalysisRun).where(AnalysisRun.id == run_id)

        if include_sessions:
            query = query.options(selectinload(AnalysisRun.detected_sessions))

        result = self.session.execute(query)
        return result.scalar_one_or_none()

    def list_analysis_runs(
        self,
        scenario_name: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by_recent: bool = True,
    ) -> List[AnalysisRun]:
        """
        List analysis runs with optional filtering.

        Args:
            scenario_name: Filter by scenario name (optional)
            limit: Maximum number of results
            offset: Number of results to skip
            order_by_recent: Sort by most recent first

        Returns:
            List of AnalysisRun instances
        """
        query = select(AnalysisRun)

        if scenario_name:
            query = query.where(AnalysisRun.scenario_name == scenario_name)

        if order_by_recent:
            query = query.order_by(desc(AnalysisRun.created_at))
        else:
            query = query.order_by(AnalysisRun.created_at)

        query = query.limit(limit).offset(offset)

        result = self.session.execute(query)
        return list(result.scalars().all())

    def get_latest_analysis_run(
        self,
        scenario_name: Optional[str] = None
    ) -> Optional[AnalysisRun]:
        """
        Get the most recent analysis run.

        Args:
            scenario_name: Filter by scenario name (optional)

        Returns:
            Most recent AnalysisRun or None
        """
        runs = self.list_analysis_runs(
            scenario_name=scenario_name,
            limit=1,
            order_by_recent=True
        )
        return runs[0] if runs else None

    def delete_analysis_run(self, run_id: int) -> bool:
        """
        Delete an analysis run and all associated data.

        Args:
            run_id: Analysis run ID

        Returns:
            True if deleted, False if not found
        """
        analysis_run = self.get_analysis_run(run_id)
        if analysis_run:
            self.session.delete(analysis_run)
            logger.info(f"Deleted analysis run {run_id}")
            return True
        return False


class SessionRepository:
    """Repository for managing DetectedSession records."""

    def __init__(self, session: Session):
        """
        Initialize repository with database session.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save_session(
        self,
        analysis_run_id: int,
        session_id: str,
        risk_score: float,
        is_malicious: bool,
        session_data: Dict[str, Any],
        num_events: int,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        duration_seconds: Optional[float] = None,
        kill_chain_stages: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        principals: Optional[List[str]] = None,
        source_ips: Optional[List[str]] = None,
        resources: Optional[List[str]] = None,
        event_types: Optional[List[str]] = None,
        iocs: Optional[Dict[str, Any]] = None,
        narrative: Optional[str] = None,
        response_plan: Optional[Dict[str, Any]] = None,
    ) -> DetectedSession:
        """
        Save a detected session to the database.

        Args:
            analysis_run_id: ID of parent analysis run
            session_id: Unique session identifier
            risk_score: Calculated risk score
            is_malicious: Whether session is malicious
            session_data: Complete session data
            num_events: Number of events in session
            start_time: Session start time
            end_time: Session end time
            duration_seconds: Session duration
            kill_chain_stages: Detected kill chain stages
            mitre_techniques: Detected MITRE ATT&CK techniques
            principals: List of principals/users
            source_ips: List of source IP addresses
            resources: List of accessed resources
            event_types: List of event types
            iocs: Extracted IOCs
            narrative: Threat narrative
            response_plan: Incident response plan

        Returns:
            Created DetectedSession instance
        """
        detected_session = DetectedSession(
            analysis_run_id=analysis_run_id,
            session_id=session_id,
            risk_score=risk_score,
            is_malicious=is_malicious,
            num_events=num_events,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration_seconds,
            kill_chain_stages=kill_chain_stages or [],
            mitre_techniques=mitre_techniques or [],
            principals=principals or [],
            source_ips=source_ips or [],
            resources=resources or [],
            event_types=event_types or [],
            iocs=iocs or {},
            narrative=narrative,
            response_plan=response_plan,
            session_data=session_data,
        )

        self.session.add(detected_session)
        self.session.flush()

        logger.info(
            f"Saved detected session {session_id} with risk score {risk_score:.2f}"
        )
        return detected_session

    def get_session(
        self,
        session_db_id: int,
        include_iocs: bool = False
    ) -> Optional[DetectedSession]:
        """
        Retrieve a detected session by database ID.

        Args:
            session_db_id: Database ID of the session
            include_iocs: Whether to eagerly load IOCs

        Returns:
            DetectedSession instance or None
        """
        query = select(DetectedSession).where(DetectedSession.id == session_db_id)

        if include_iocs:
            query = query.options(selectinload(DetectedSession.ioc_records))

        result = self.session.execute(query)
        return result.scalar_one_or_none()

    def get_session_by_session_id(
        self,
        session_id: str
    ) -> Optional[DetectedSession]:
        """
        Retrieve a detected session by session ID string.

        Args:
            session_id: Session identifier string

        Returns:
            DetectedSession instance or None
        """
        query = select(DetectedSession).where(
            DetectedSession.session_id == session_id
        )
        result = self.session.execute(query)
        return result.scalar_one_or_none()

    def get_sessions_by_analysis_run(
        self,
        analysis_run_id: int,
        include_iocs: bool = False
    ) -> List[DetectedSession]:
        """
        Get all sessions for an analysis run.

        Args:
            analysis_run_id: Analysis run ID
            include_iocs: Whether to eagerly load IOCs

        Returns:
            List of DetectedSession instances
        """
        query = select(DetectedSession).where(
            DetectedSession.analysis_run_id == analysis_run_id
        )

        if include_iocs:
            query = query.options(selectinload(DetectedSession.ioc_records))

        result = self.session.execute(query)
        return list(result.scalars().all())

    def get_sessions_by_risk(
        self,
        min_risk_score: float = 0.0,
        max_risk_score: float = 1.0,
        malicious_only: bool = False,
        limit: int = 100,
    ) -> List[DetectedSession]:
        """
        Get sessions filtered by risk score.

        Args:
            min_risk_score: Minimum risk score
            max_risk_score: Maximum risk score
            malicious_only: Only return malicious sessions
            limit: Maximum number of results

        Returns:
            List of DetectedSession instances
        """
        query = select(DetectedSession).where(
            DetectedSession.risk_score >= min_risk_score,
            DetectedSession.risk_score <= max_risk_score,
        )

        if malicious_only:
            query = query.where(DetectedSession.is_malicious == True)

        query = query.order_by(desc(DetectedSession.risk_score)).limit(limit)

        result = self.session.execute(query)
        return list(result.scalars().all())

    def get_sessions_by_mitre_technique(
        self,
        technique: str
    ) -> List[DetectedSession]:
        """
        Get sessions that use a specific MITRE ATT&CK technique.

        Args:
            technique: MITRE technique ID (e.g., 'T1078')

        Returns:
            List of DetectedSession instances
        """
        # Using PostgreSQL JSONB contains operator
        query = select(DetectedSession).where(
            DetectedSession.mitre_techniques.contains([technique])
        )

        result = self.session.execute(query)
        return list(result.scalars().all())


class IOCRepository:
    """Repository for managing IOC records."""

    def __init__(self, session: Session):
        """
        Initialize repository with database session.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save_ioc(
        self,
        session_id: int,
        ioc_type: str,
        value: str,
        severity: str = "medium",
        context: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
    ) -> IOC:
        """
        Save an IOC to the database.

        Args:
            session_id: Database ID of the detected session
            ioc_type: Type of IOC (ip, domain, url, hash, etc.)
            value: IOC value
            severity: Severity level (low, medium, high, critical)
            context: Context where IOC was found
            metadata: Additional metadata
            first_seen: First seen timestamp
            last_seen: Last seen timestamp

        Returns:
            Created IOC instance
        """
        ioc = IOC(
            session_id=session_id,
            ioc_type=ioc_type,
            value=value,
            severity=severity,
            context=context,
            metadata=metadata or {},
            first_seen=first_seen or datetime.utcnow(),
            last_seen=last_seen or datetime.utcnow(),
        )

        self.session.add(ioc)
        self.session.flush()

        logger.info(f"Saved IOC: {ioc_type}={value}")
        return ioc

    def save_iocs(
        self,
        session_id: int,
        iocs_data: Dict[str, List[Dict[str, Any]]]
    ) -> List[IOC]:
        """
        Save multiple IOCs from a dictionary structure.

        Args:
            session_id: Database ID of the detected session
            iocs_data: Dictionary mapping IOC types to lists of IOC data

        Returns:
            List of created IOC instances
        """
        created_iocs = []

        for ioc_type, ioc_list in iocs_data.items():
            for ioc_data in ioc_list:
                ioc = self.save_ioc(
                    session_id=session_id,
                    ioc_type=ioc_type,
                    value=ioc_data.get("value", ""),
                    severity=ioc_data.get("severity", "medium"),
                    context=ioc_data.get("context"),
                    metadata=ioc_data.get("metadata", {}),
                )
                created_iocs.append(ioc)

        logger.info(f"Saved {len(created_iocs)} IOCs for session {session_id}")
        return created_iocs

    def get_ioc(self, ioc_id: int) -> Optional[IOC]:
        """
        Retrieve an IOC by ID.

        Args:
            ioc_id: IOC database ID

        Returns:
            IOC instance or None
        """
        query = select(IOC).where(IOC.id == ioc_id)
        result = self.session.execute(query)
        return result.scalar_one_or_none()

    def get_iocs_by_session(
        self,
        session_id: int,
        include_threat_intel: bool = False
    ) -> List[IOC]:
        """
        Get all IOCs for a detected session.

        Args:
            session_id: Database ID of the detected session
            include_threat_intel: Whether to eagerly load threat intelligence

        Returns:
            List of IOC instances
        """
        query = select(IOC).where(IOC.session_id == session_id)

        if include_threat_intel:
            query = query.options(selectinload(IOC.threat_intel))

        result = self.session.execute(query)
        return list(result.scalars().all())

    def get_iocs_by_type(
        self,
        ioc_type: str,
        limit: int = 100
    ) -> List[IOC]:
        """
        Get IOCs by type.

        Args:
            ioc_type: Type of IOC (ip, domain, url, hash, etc.)
            limit: Maximum number of results

        Returns:
            List of IOC instances
        """
        query = select(IOC).where(IOC.ioc_type == ioc_type).limit(limit)
        result = self.session.execute(query)
        return list(result.scalars().all())

    def get_iocs_by_value(self, value: str) -> List[IOC]:
        """
        Get IOCs by exact value match.

        Args:
            value: IOC value to search for

        Returns:
            List of IOC instances
        """
        query = select(IOC).where(IOC.value == value)
        result = self.session.execute(query)
        return list(result.scalars().all())

    def get_iocs_by_severity(
        self,
        severity: str,
        limit: int = 100
    ) -> List[IOC]:
        """
        Get IOCs by severity level.

        Args:
            severity: Severity level (low, medium, high, critical)
            limit: Maximum number of results

        Returns:
            List of IOC instances
        """
        query = select(IOC).where(IOC.severity == severity).limit(limit)
        result = self.session.execute(query)
        return list(result.scalars().all())

    def update_ioc_enrichment(
        self,
        ioc_id: int,
        enriched: bool = True
    ) -> Optional[IOC]:
        """
        Mark an IOC as enriched with threat intelligence.

        Args:
            ioc_id: IOC database ID
            enriched: Enrichment status

        Returns:
            Updated IOC or None
        """
        ioc = self.get_ioc(ioc_id)
        if ioc:
            ioc.enriched = enriched
            self.session.flush()
            logger.info(f"Updated IOC {ioc_id} enrichment status to {enriched}")
        return ioc


class ThreatIntelligenceRepository:
    """Repository for managing ThreatIntelligence records."""

    def __init__(self, session: Session):
        """
        Initialize repository with database session.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save_threat_intelligence(
        self,
        ioc_id: int,
        provider: str,
        is_malicious: bool,
        raw_response: Dict[str, Any],
        reputation_score: Optional[float] = None,
        confidence: Optional[float] = None,
        threat_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        notes: Optional[str] = None,
    ) -> ThreatIntelligence:
        """
        Save threat intelligence data for an IOC.

        Args:
            ioc_id: Database ID of the IOC
            provider: Threat intelligence provider name
            is_malicious: Whether IOC is confirmed malicious
            raw_response: Raw API response from provider
            reputation_score: Reputation score
            confidence: Confidence level
            threat_types: List of threat types
            tags: List of tags
            notes: Additional notes

        Returns:
            Created ThreatIntelligence instance
        """
        threat_intel = ThreatIntelligence(
            ioc_id=ioc_id,
            provider=provider,
            is_malicious=is_malicious,
            reputation_score=reputation_score,
            confidence=confidence,
            threat_types=threat_types or [],
            tags=tags or [],
            raw_response=raw_response,
            notes=notes,
        )

        self.session.add(threat_intel)
        self.session.flush()

        logger.info(
            f"Saved threat intelligence from {provider} for IOC {ioc_id}"
        )
        return threat_intel

    def get_threat_intelligence(
        self,
        intel_id: int
    ) -> Optional[ThreatIntelligence]:
        """
        Retrieve threat intelligence by ID.

        Args:
            intel_id: Threat intelligence database ID

        Returns:
            ThreatIntelligence instance or None
        """
        query = select(ThreatIntelligence).where(ThreatIntelligence.id == intel_id)
        result = self.session.execute(query)
        return result.scalar_one_or_none()

    def get_threat_intelligence_by_ioc(
        self,
        ioc_id: int
    ) -> List[ThreatIntelligence]:
        """
        Get all threat intelligence for an IOC.

        Args:
            ioc_id: Database ID of the IOC

        Returns:
            List of ThreatIntelligence instances
        """
        query = select(ThreatIntelligence).where(
            ThreatIntelligence.ioc_id == ioc_id
        )
        result = self.session.execute(query)
        return list(result.scalars().all())

    def get_threat_intelligence_by_provider(
        self,
        provider: str,
        limit: int = 100
    ) -> List[ThreatIntelligence]:
        """
        Get threat intelligence by provider.

        Args:
            provider: Provider name
            limit: Maximum number of results

        Returns:
            List of ThreatIntelligence instances
        """
        query = select(ThreatIntelligence).where(
            ThreatIntelligence.provider == provider
        ).limit(limit)
        result = self.session.execute(query)
        return list(result.scalars().all())

    def get_malicious_iocs(
        self,
        provider: Optional[str] = None,
        limit: int = 100
    ) -> List[ThreatIntelligence]:
        """
        Get threat intelligence records for confirmed malicious IOCs.

        Args:
            provider: Optional provider filter
            limit: Maximum number of results

        Returns:
            List of ThreatIntelligence instances
        """
        query = select(ThreatIntelligence).where(
            ThreatIntelligence.is_malicious == True
        )

        if provider:
            query = query.where(ThreatIntelligence.provider == provider)

        query = query.order_by(
            desc(ThreatIntelligence.last_checked)
        ).limit(limit)

        result = self.session.execute(query)
        return list(result.scalars().all())
