"""
Example usage of the AI Threat Hunting Simulator database persistence layer.

This script demonstrates how to use the database layer to persist and retrieve
threat hunting analysis results.
"""
from datetime import datetime
from pathlib import Path

from .database import DatabaseConfig, init_database
from .repository import (
    AnalysisRepository,
    IOCRepository,
    SessionRepository,
    ThreatIntelligenceRepository,
)


def example_basic_usage():
    """Example: Basic database initialization and usage."""
    print("\n=== Example 1: Basic Database Usage ===\n")

    # Initialize SQLite database
    config = DatabaseConfig.sqlite_file("threat_hunting.db")
    db = init_database(config, create_tables=True)

    # Use session scope for automatic transaction management
    with db.session_scope() as session:
        # Create repositories
        analysis_repo = AnalysisRepository(session)

        # Save an analysis run
        analysis_run = analysis_repo.save_analysis_run(
            scenario_name="credential_stuffing_attack",
            num_events=1500,
            num_sessions=75,
            num_suspicious_sessions=5,
            results={
                "total_events": 1500,
                "total_sessions": 75,
                "suspicious_sessions": 5,
                "sessions": [],
            },
            telemetry_file_path="/data/telemetry/cred_stuffing.jsonl",
            analysis_duration_seconds=45.2,
        )

        print(f"Created analysis run: {analysis_run}")
        print(f"Analysis run ID: {analysis_run.id}")

    # Retrieve analysis runs
    with db.session_scope() as session:
        analysis_repo = AnalysisRepository(session)

        # Get latest run
        latest_run = analysis_repo.get_latest_analysis_run()
        print(f"\nLatest analysis run: {latest_run}")

        # List all runs
        all_runs = analysis_repo.list_analysis_runs(limit=10)
        print(f"\nTotal analysis runs: {len(all_runs)}")


def example_save_session_with_iocs():
    """Example: Save detected session with IOCs."""
    print("\n=== Example 2: Save Session with IOCs ===\n")

    config = DatabaseConfig.sqlite_file("threat_hunting.db")
    db = init_database(config, create_tables=True)

    with db.session_scope() as session:
        # Create repositories
        analysis_repo = AnalysisRepository(session)
        session_repo = SessionRepository(session)
        ioc_repo = IOCRepository(session)

        # First, create an analysis run
        analysis_run = analysis_repo.save_analysis_run(
            scenario_name="iam_privilege_escalation",
            num_events=500,
            num_sessions=20,
            num_suspicious_sessions=3,
            results={"sessions": []},
        )

        # Save a detected session
        detected_session = session_repo.save_session(
            analysis_run_id=analysis_run.id,
            session_id="session-attacker-192.168.1.100-0",
            risk_score=0.85,
            is_malicious=True,
            num_events=25,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            duration_seconds=120.5,
            kill_chain_stages=["reconnaissance", "privilege_escalation"],
            mitre_techniques=["T1078", "T1098"],
            principals=["compromised-user@example.com"],
            source_ips=["192.168.1.100"],
            resources=["arn:aws:iam::123456789012:role/AdminRole"],
            event_types=["iam.create_role", "iam.attach_policy"],
            narrative="Detected privilege escalation attempt via IAM role creation",
            session_data={
                "session_id": "session-attacker-192.168.1.100-0",
                "events": [],
            },
        )

        print(f"Created detected session: {detected_session}")

        # Save IOCs for the session
        iocs_data = {
            "ip": [
                {"value": "192.168.1.100", "severity": "high"},
                {"value": "10.0.0.50", "severity": "medium"},
            ],
            "domain": [
                {"value": "malicious.example.com", "severity": "critical"},
            ],
        }

        iocs = ioc_repo.save_iocs(
            session_id=detected_session.id,
            iocs_data=iocs_data,
        )

        print(f"\nCreated {len(iocs)} IOCs:")
        for ioc in iocs:
            print(f"  - {ioc}")


def example_query_sessions():
    """Example: Query detected sessions."""
    print("\n=== Example 3: Query Detected Sessions ===\n")

    config = DatabaseConfig.sqlite_file("threat_hunting.db")
    db = init_database(config, create_tables=True)

    with db.session_scope() as session:
        session_repo = SessionRepository(session)

        # Get high-risk sessions
        high_risk_sessions = session_repo.get_sessions_by_risk(
            min_risk_score=0.7,
            malicious_only=True,
            limit=10,
        )

        print(f"Found {len(high_risk_sessions)} high-risk sessions:")
        for s in high_risk_sessions:
            print(f"  - {s.session_id}: risk={s.risk_score:.2f}")

        # Query by MITRE technique
        if high_risk_sessions:
            # This would work with PostgreSQL JSONB
            # technique_sessions = session_repo.get_sessions_by_mitre_technique("T1078")
            # print(f"\nSessions using T1078: {len(technique_sessions)}")
            pass


def example_threat_intelligence():
    """Example: Add threat intelligence to IOCs."""
    print("\n=== Example 4: Threat Intelligence ===\n")

    config = DatabaseConfig.sqlite_file("threat_hunting.db")
    db = init_database(config, create_tables=True)

    with db.session_scope() as session:
        # Create necessary data first
        analysis_repo = AnalysisRepository(session)
        session_repo = SessionRepository(session)
        ioc_repo = IOCRepository(session)
        intel_repo = ThreatIntelligenceRepository(session)

        # Create analysis run and session
        analysis_run = analysis_repo.save_analysis_run(
            scenario_name="malware_c2",
            num_events=200,
            num_sessions=10,
            results={},
        )

        detected_session = session_repo.save_session(
            analysis_run_id=analysis_run.id,
            session_id="session-malware-c2-001",
            risk_score=0.95,
            is_malicious=True,
            num_events=15,
            session_data={"events": []},
        )

        # Create an IOC
        ioc = ioc_repo.save_ioc(
            session_id=detected_session.id,
            ioc_type="ip",
            value="203.0.113.50",
            severity="critical",
            context="Command and control communication",
        )

        print(f"Created IOC: {ioc}")

        # Add threat intelligence from VirusTotal
        threat_intel = intel_repo.save_threat_intelligence(
            ioc_id=ioc.id,
            provider="virustotal",
            is_malicious=True,
            reputation_score=0.95,
            confidence=0.9,
            threat_types=["malware", "c2"],
            tags=["apt", "botnet"],
            raw_response={
                "positives": 45,
                "total": 50,
                "scan_date": "2024-01-15",
            },
            notes="Known C2 server for APT group",
        )

        print(f"Added threat intelligence: {threat_intel}")

        # Update IOC enrichment status
        ioc_repo.update_ioc_enrichment(ioc.id, enriched=True)
        print(f"IOC marked as enriched")

        # Query threat intelligence
        all_intel = intel_repo.get_threat_intelligence_by_ioc(ioc.id)
        print(f"\nThreat intelligence records: {len(all_intel)}")


def example_async_usage():
    """Example: Async database operations."""
    print("\n=== Example 5: Async Database Operations ===\n")

    # Note: This requires asyncio and asyncpg for PostgreSQL
    import asyncio

    async def async_example():
        from .database import init_async_database

        # For PostgreSQL async
        config = DatabaseConfig.postgresql_async(
            host="localhost",
            database="threat_hunting",
            user="postgres",
            password="password",
        )

        # Initialize async database
        db = await init_async_database(config, create_tables=True)

        # Use async session scope
        async with db.session_scope() as session:
            from .repository import AnalysisRepository

            analysis_repo = AnalysisRepository(session)

            # Async operations work the same way
            analysis_run = analysis_repo.save_analysis_run(
                scenario_name="async_analysis",
                num_events=1000,
                num_sessions=50,
                results={},
            )
            print(f"Created analysis run (async): {analysis_run}")

        await db.dispose()

    # Uncomment to run async example
    # asyncio.run(async_example())
    print("Async example code available (requires PostgreSQL + asyncpg)")


if __name__ == "__main__":
    """Run all examples."""
    print("=" * 70)
    print("AI Threat Hunting Simulator - Database Usage Examples")
    print("=" * 70)

    # Run examples
    example_basic_usage()
    example_save_session_with_iocs()
    example_query_sessions()
    example_threat_intelligence()
    example_async_usage()

    print("\n" + "=" * 70)
    print("All examples completed successfully!")
    print("=" * 70)
