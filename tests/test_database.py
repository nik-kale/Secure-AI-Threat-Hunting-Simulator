"""
Unit tests for the database persistence layer.

Run with: pytest analysis_engine/database/test_database.py
"""
import pytest
from datetime import datetime
from pathlib import Path
import tempfile

from .database import DatabaseConfig, DatabaseManager
from .models import AnalysisRun, DetectedSession, IOC, ThreatIntelligence
from .repository import (
    AnalysisRepository,
    SessionRepository,
    IOCRepository,
    ThreatIntelligenceRepository,
)


@pytest.fixture
def db_manager():
    """Create in-memory database for testing."""
    config = DatabaseConfig.sqlite_memory()
    db = DatabaseManager(config)
    db.create_all()
    yield db
    db.dispose()


@pytest.fixture
def session(db_manager):
    """Provide database session for testing."""
    with db_manager.session_scope() as sess:
        yield sess


class TestDatabaseModels:
    """Test SQLAlchemy models."""

    def test_analysis_run_creation(self, session):
        """Test creating an AnalysisRun."""
        run = AnalysisRun(
            scenario_name="test_scenario",
            num_events=100,
            num_sessions=10,
            results={"test": "data"},
        )
        session.add(run)
        session.flush()

        assert run.id is not None
        assert run.scenario_name == "test_scenario"
        assert run.num_events == 100
        assert run.created_at is not None

    def test_detected_session_creation(self, session):
        """Test creating a DetectedSession."""
        # First create analysis run
        run = AnalysisRun(
            scenario_name="test",
            num_events=50,
            num_sessions=5,
            results={},
        )
        session.add(run)
        session.flush()

        # Create detected session
        detected = DetectedSession(
            analysis_run_id=run.id,
            session_id="test-session-001",
            risk_score=0.85,
            is_malicious=True,
            num_events=10,
            session_data={"events": []},
        )
        session.add(detected)
        session.flush()

        assert detected.id is not None
        assert detected.session_id == "test-session-001"
        assert detected.risk_score == 0.85
        assert detected.is_malicious is True

    def test_ioc_creation(self, session):
        """Test creating an IOC."""
        # Create parent objects
        run = AnalysisRun(
            scenario_name="test",
            num_events=50,
            num_sessions=5,
            results={},
        )
        session.add(run)
        session.flush()

        detected = DetectedSession(
            analysis_run_id=run.id,
            session_id="test-session",
            risk_score=0.7,
            is_malicious=True,
            num_events=5,
            session_data={},
        )
        session.add(detected)
        session.flush()

        # Create IOC
        ioc = IOC(
            session_id=detected.id,
            ioc_type="ip",
            value="192.168.1.100",
            severity="high",
        )
        session.add(ioc)
        session.flush()

        assert ioc.id is not None
        assert ioc.ioc_type == "ip"
        assert ioc.value == "192.168.1.100"
        assert ioc.severity == "high"

    def test_threat_intelligence_creation(self, session):
        """Test creating ThreatIntelligence."""
        # Create all parent objects
        run = AnalysisRun(
            scenario_name="test",
            num_events=50,
            num_sessions=5,
            results={},
        )
        session.add(run)
        session.flush()

        detected = DetectedSession(
            analysis_run_id=run.id,
            session_id="test-session",
            risk_score=0.7,
            is_malicious=True,
            num_events=5,
            session_data={},
        )
        session.add(detected)
        session.flush()

        ioc = IOC(
            session_id=detected.id,
            ioc_type="ip",
            value="203.0.113.50",
            severity="critical",
        )
        session.add(ioc)
        session.flush()

        # Create threat intelligence
        intel = ThreatIntelligence(
            ioc_id=ioc.id,
            provider="virustotal",
            is_malicious=True,
            reputation_score=0.95,
            raw_response={"positives": 45, "total": 50},
        )
        session.add(intel)
        session.flush()

        assert intel.id is not None
        assert intel.provider == "virustotal"
        assert intel.is_malicious is True
        assert intel.reputation_score == 0.95


class TestAnalysisRepository:
    """Test AnalysisRepository."""

    def test_save_analysis_run(self, session):
        """Test saving an analysis run."""
        repo = AnalysisRepository(session)

        run = repo.save_analysis_run(
            scenario_name="credential_stuffing",
            num_events=1000,
            num_sessions=50,
            results={"sessions": []},
            num_suspicious_sessions=5,
        )

        assert run.id is not None
        assert run.scenario_name == "credential_stuffing"
        assert run.num_suspicious_sessions == 5

    def test_get_analysis_run(self, session):
        """Test retrieving an analysis run."""
        repo = AnalysisRepository(session)

        # Create run
        created_run = repo.save_analysis_run(
            scenario_name="test_scenario",
            num_events=100,
            num_sessions=10,
            results={},
        )

        # Retrieve it
        retrieved_run = repo.get_analysis_run(created_run.id)

        assert retrieved_run is not None
        assert retrieved_run.id == created_run.id
        assert retrieved_run.scenario_name == "test_scenario"

    def test_list_analysis_runs(self, session):
        """Test listing analysis runs."""
        repo = AnalysisRepository(session)

        # Create multiple runs
        for i in range(5):
            repo.save_analysis_run(
                scenario_name=f"scenario_{i}",
                num_events=100 * i,
                num_sessions=10 * i,
                results={},
            )

        # List all runs
        runs = repo.list_analysis_runs(limit=10)
        assert len(runs) == 5

    def test_get_latest_analysis_run(self, session):
        """Test getting the latest analysis run."""
        repo = AnalysisRepository(session)

        # Create runs
        for i in range(3):
            repo.save_analysis_run(
                scenario_name="test",
                num_events=100,
                num_sessions=10,
                results={},
            )

        # Get latest
        latest = repo.get_latest_analysis_run()
        assert latest is not None


class TestSessionRepository:
    """Test SessionRepository."""

    def test_save_session(self, session):
        """Test saving a detected session."""
        # Create analysis run first
        analysis_repo = AnalysisRepository(session)
        run = analysis_repo.save_analysis_run(
            scenario_name="test",
            num_events=100,
            num_sessions=10,
            results={},
        )

        # Save session
        session_repo = SessionRepository(session)
        detected_session = session_repo.save_session(
            analysis_run_id=run.id,
            session_id="test-session-001",
            risk_score=0.85,
            is_malicious=True,
            num_events=10,
            session_data={"events": []},
        )

        assert detected_session.id is not None
        assert detected_session.risk_score == 0.85

    def test_get_sessions_by_risk(self, session):
        """Test querying sessions by risk score."""
        # Setup
        analysis_repo = AnalysisRepository(session)
        session_repo = SessionRepository(session)

        run = analysis_repo.save_analysis_run(
            scenario_name="test",
            num_events=100,
            num_sessions=10,
            results={},
        )

        # Create sessions with different risk scores
        for i, risk in enumerate([0.3, 0.6, 0.9]):
            session_repo.save_session(
                analysis_run_id=run.id,
                session_id=f"session-{i}",
                risk_score=risk,
                is_malicious=risk > 0.5,
                num_events=5,
                session_data={},
            )

        # Query high-risk sessions
        high_risk = session_repo.get_sessions_by_risk(
            min_risk_score=0.7,
            malicious_only=True,
        )

        assert len(high_risk) == 1
        assert high_risk[0].risk_score == 0.9


class TestIOCRepository:
    """Test IOCRepository."""

    def test_save_ioc(self, session):
        """Test saving an IOC."""
        # Setup
        analysis_repo = AnalysisRepository(session)
        session_repo = SessionRepository(session)
        ioc_repo = IOCRepository(session)

        run = analysis_repo.save_analysis_run(
            scenario_name="test",
            num_events=100,
            num_sessions=10,
            results={},
        )

        detected_session = session_repo.save_session(
            analysis_run_id=run.id,
            session_id="test-session",
            risk_score=0.8,
            is_malicious=True,
            num_events=5,
            session_data={},
        )

        # Save IOC
        ioc = ioc_repo.save_ioc(
            session_id=detected_session.id,
            ioc_type="ip",
            value="192.168.1.100",
            severity="high",
        )

        assert ioc.id is not None
        assert ioc.value == "192.168.1.100"

    def test_save_iocs_bulk(self, session):
        """Test saving multiple IOCs at once."""
        # Setup
        analysis_repo = AnalysisRepository(session)
        session_repo = SessionRepository(session)
        ioc_repo = IOCRepository(session)

        run = analysis_repo.save_analysis_run(
            scenario_name="test",
            num_events=100,
            num_sessions=10,
            results={},
        )

        detected_session = session_repo.save_session(
            analysis_run_id=run.id,
            session_id="test-session",
            risk_score=0.8,
            is_malicious=True,
            num_events=5,
            session_data={},
        )

        # Save multiple IOCs
        iocs_data = {
            "ip": [
                {"value": "192.168.1.100", "severity": "high"},
                {"value": "10.0.0.50", "severity": "medium"},
            ],
            "domain": [
                {"value": "evil.com", "severity": "critical"},
            ],
        }

        iocs = ioc_repo.save_iocs(detected_session.id, iocs_data)

        assert len(iocs) == 3

    def test_get_iocs_by_type(self, session):
        """Test querying IOCs by type."""
        # Setup
        analysis_repo = AnalysisRepository(session)
        session_repo = SessionRepository(session)
        ioc_repo = IOCRepository(session)

        run = analysis_repo.save_analysis_run(
            scenario_name="test",
            num_events=100,
            num_sessions=10,
            results={},
        )

        detected_session = session_repo.save_session(
            analysis_run_id=run.id,
            session_id="test-session",
            risk_score=0.8,
            is_malicious=True,
            num_events=5,
            session_data={},
        )

        # Create different types of IOCs
        ioc_repo.save_ioc(detected_session.id, "ip", "192.168.1.1", "high")
        ioc_repo.save_ioc(detected_session.id, "ip", "10.0.0.1", "medium")
        ioc_repo.save_ioc(detected_session.id, "domain", "evil.com", "critical")

        # Query by type
        ip_iocs = ioc_repo.get_iocs_by_type("ip")
        assert len(ip_iocs) == 2

        domain_iocs = ioc_repo.get_iocs_by_type("domain")
        assert len(domain_iocs) == 1


class TestThreatIntelligenceRepository:
    """Test ThreatIntelligenceRepository."""

    def test_save_threat_intelligence(self, session):
        """Test saving threat intelligence."""
        # Setup complete hierarchy
        analysis_repo = AnalysisRepository(session)
        session_repo = SessionRepository(session)
        ioc_repo = IOCRepository(session)
        intel_repo = ThreatIntelligenceRepository(session)

        run = analysis_repo.save_analysis_run(
            scenario_name="test",
            num_events=100,
            num_sessions=10,
            results={},
        )

        detected_session = session_repo.save_session(
            analysis_run_id=run.id,
            session_id="test-session",
            risk_score=0.8,
            is_malicious=True,
            num_events=5,
            session_data={},
        )

        ioc = ioc_repo.save_ioc(
            session_id=detected_session.id,
            ioc_type="ip",
            value="203.0.113.50",
            severity="critical",
        )

        # Save threat intelligence
        intel = intel_repo.save_threat_intelligence(
            ioc_id=ioc.id,
            provider="virustotal",
            is_malicious=True,
            reputation_score=0.95,
            raw_response={"positives": 45, "total": 50},
        )

        assert intel.id is not None
        assert intel.provider == "virustotal"
        assert intel.is_malicious is True

    def test_get_malicious_iocs(self, session):
        """Test querying malicious IOCs."""
        # Setup
        analysis_repo = AnalysisRepository(session)
        session_repo = SessionRepository(session)
        ioc_repo = IOCRepository(session)
        intel_repo = ThreatIntelligenceRepository(session)

        run = analysis_repo.save_analysis_run(
            scenario_name="test",
            num_events=100,
            num_sessions=10,
            results={},
        )

        detected_session = session_repo.save_session(
            analysis_run_id=run.id,
            session_id="test-session",
            risk_score=0.8,
            is_malicious=True,
            num_events=5,
            session_data={},
        )

        # Create IOCs with different threat levels
        ioc1 = ioc_repo.save_ioc(
            detected_session.id, "ip", "203.0.113.50", "critical"
        )
        ioc2 = ioc_repo.save_ioc(
            detected_session.id, "ip", "198.51.100.1", "low"
        )

        intel_repo.save_threat_intelligence(
            ioc1.id, "virustotal", True, 0.95, {"positives": 45}
        )
        intel_repo.save_threat_intelligence(
            ioc2.id, "virustotal", False, 0.05, {"positives": 1}
        )

        # Query malicious IOCs
        malicious = intel_repo.get_malicious_iocs()
        assert len(malicious) == 1
        assert malicious[0].ioc_id == ioc1.id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
