"""
Database persistence layer for AI Threat Hunting Simulator.

This package provides SQLAlchemy-based data persistence for threat hunting
analysis results, including models, database configuration, and repositories.

Example usage:

    from analysis_engine.database import (
        DatabaseConfig,
        init_database,
        AnalysisRepository,
        SessionRepository,
        IOCRepository,
    )

    # Initialize database
    config = DatabaseConfig.sqlite_file("threat_hunting.db")
    db = init_database(config)

    # Use repositories
    with db.session_scope() as session:
        analysis_repo = AnalysisRepository(session)
        run = analysis_repo.save_analysis_run(
            scenario_name="credential_stuffing",
            num_events=1000,
            num_sessions=50,
            results={"sessions": [...]},
        )
"""

# Models
from .models import (
    AnalysisRun,
    Base,
    DetectedSession,
    IOC,
    ThreatIntelligence,
)

# Database configuration and management
from .database import (
    AsyncDatabaseManager,
    DatabaseConfig,
    DatabaseManager,
    get_async_database,
    get_database,
    init_async_database,
    init_database,
)

# Repositories
from .repository import (
    AnalysisRepository,
    IOCRepository,
    SessionRepository,
    ThreatIntelligenceRepository,
)

__all__ = [
    # Models
    "Base",
    "AnalysisRun",
    "DetectedSession",
    "IOC",
    "ThreatIntelligence",
    # Database
    "DatabaseConfig",
    "DatabaseManager",
    "AsyncDatabaseManager",
    "init_database",
    "init_async_database",
    "get_database",
    "get_async_database",
    # Repositories
    "AnalysisRepository",
    "SessionRepository",
    "IOCRepository",
    "ThreatIntelligenceRepository",
]

__version__ = "1.0.0"
