"""
Integration example: Using the database layer with the analysis pipeline.

This module demonstrates how to integrate the database persistence layer
with the existing threat hunting analysis pipeline to automatically save
results to the database.
"""
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import time
import logging

# Database imports
from .database import DatabaseConfig, init_database
from .repository import (
    AnalysisRepository,
    SessionRepository,
    IOCRepository,
)

logger = logging.getLogger(__name__)


class DatabasePersistentPipeline:
    """
    Threat hunting pipeline with automatic database persistence.

    This class wraps the standard ThreatHuntingPipeline and automatically
    saves all analysis results to the database.
    """

    def __init__(
        self,
        database_url: str,
        time_window_minutes: int = 60,
        min_events_for_session: int = 3,
        risk_threshold: float = 0.5,
    ):
        """
        Initialize pipeline with database persistence.

        Args:
            database_url: Database connection URL
            time_window_minutes: Correlation time window
            min_events_for_session: Minimum events for session
            risk_threshold: Risk score threshold
        """
        # Initialize database
        config = DatabaseConfig.from_url(database_url)
        self.db = init_database(config, create_tables=True)

        # Import and initialize pipeline
        from ..pipeline import ThreatHuntingPipeline

        self.pipeline = ThreatHuntingPipeline(
            time_window_minutes=time_window_minutes,
            min_events_for_session=min_events_for_session,
            risk_threshold=risk_threshold,
        )

        self.time_window_minutes = time_window_minutes
        self.min_events_for_session = min_events_for_session
        self.risk_threshold = risk_threshold

    def analyze_and_save(
        self,
        telemetry_path: Path,
        scenario_name: Optional[str] = None,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Analyze telemetry and save results to database.

        Args:
            telemetry_path: Path to telemetry file
            scenario_name: Name of scenario (defaults to filename)
            output_dir: Optional output directory for reports

        Returns:
            Analysis results with database IDs
        """
        # Use filename as scenario name if not provided
        if scenario_name is None:
            scenario_name = telemetry_path.stem

        logger.info(f"Starting analysis of {scenario_name}")
        start_time = time.time()

        # Run analysis
        results = self.pipeline.analyze_telemetry_file(
            telemetry_path=telemetry_path,
            output_dir=output_dir,
        )

        analysis_duration = time.time() - start_time

        # Save to database
        db_results = self._save_to_database(
            scenario_name=scenario_name,
            telemetry_path=telemetry_path,
            results=results,
            analysis_duration=analysis_duration,
        )

        logger.info(
            f"Analysis complete. Saved to database as run ID {db_results['analysis_run_id']}"
        )

        return db_results

    def _save_to_database(
        self,
        scenario_name: str,
        telemetry_path: Path,
        results: Dict[str, Any],
        analysis_duration: float,
    ) -> Dict[str, Any]:
        """
        Save analysis results to database.

        Args:
            scenario_name: Scenario name
            telemetry_path: Path to telemetry file
            results: Analysis results
            analysis_duration: Analysis duration in seconds

        Returns:
            Dictionary with database IDs
        """
        with self.db.session_scope() as session:
            analysis_repo = AnalysisRepository(session)
            session_repo = SessionRepository(session)
            ioc_repo = IOCRepository(session)

            # Save analysis run
            analysis_run = analysis_repo.save_analysis_run(
                scenario_name=scenario_name,
                num_events=results.get("total_events", 0),
                num_sessions=results.get("total_sessions", 0),
                num_suspicious_sessions=results.get("suspicious_sessions", 0),
                results=results,
                time_window_minutes=self.time_window_minutes,
                min_events_for_session=self.min_events_for_session,
                risk_threshold=self.risk_threshold,
                telemetry_file_path=str(telemetry_path),
                analysis_duration_seconds=analysis_duration,
            )

            session_ids = []

            # Save each detected session
            for session_result in results.get("sessions", []):
                session_info = session_result.get("session_info", {})

                # Parse timestamps
                start_time = None
                end_time = None
                if session_info.get("start_time"):
                    start_time = datetime.fromisoformat(session_info["start_time"])
                if session_info.get("end_time"):
                    end_time = datetime.fromisoformat(session_info["end_time"])

                # Save session
                detected_session = session_repo.save_session(
                    analysis_run_id=analysis_run.id,
                    session_id=session_info.get("session_id", "unknown"),
                    risk_score=session_info.get("risk_score", 0.0),
                    is_malicious=session_info.get("is_malicious", False),
                    num_events=session_info.get("num_events", 0),
                    start_time=start_time,
                    end_time=end_time,
                    duration_seconds=session_info.get("duration_seconds"),
                    kill_chain_stages=session_result.get("kill_chain", {}).get("stages", []),
                    mitre_techniques=session_result.get("mitre", {}).get("techniques", []),
                    principals=session_info.get("principals", []),
                    source_ips=session_info.get("source_ips", []),
                    resources=session_info.get("resources", []),
                    event_types=session_info.get("event_types", []),
                    iocs=session_result.get("iocs", {}),
                    narrative=session_result.get("narrative", {}).get("summary"),
                    response_plan=session_result.get("response_plan"),
                    session_data=session_result,
                )

                session_ids.append(detected_session.id)

                # Save IOCs if present
                iocs_data = session_result.get("iocs", {})
                if iocs_data:
                    ioc_repo.save_iocs(
                        session_id=detected_session.id,
                        iocs_data=iocs_data,
                    )

            return {
                "analysis_run_id": analysis_run.id,
                "session_ids": session_ids,
                "num_sessions_saved": len(session_ids),
                "scenario_name": scenario_name,
            }

    def get_latest_analysis(self, scenario_name: Optional[str] = None) -> Optional[Dict]:
        """
        Retrieve the most recent analysis results.

        Args:
            scenario_name: Optional scenario filter

        Returns:
            Analysis results or None
        """
        with self.db.session_scope() as session:
            analysis_repo = AnalysisRepository(session)
            latest_run = analysis_repo.get_latest_analysis_run(scenario_name)

            if latest_run:
                return latest_run.results

        return None

    def get_high_risk_sessions(
        self,
        min_risk_score: float = 0.7,
        limit: int = 100,
    ):
        """
        Retrieve high-risk sessions from database.

        Args:
            min_risk_score: Minimum risk score
            limit: Maximum number of results

        Returns:
            List of high-risk sessions
        """
        with self.db.session_scope() as session:
            session_repo = SessionRepository(session)
            return session_repo.get_sessions_by_risk(
                min_risk_score=min_risk_score,
                malicious_only=True,
                limit=limit,
            )


def example_integration():
    """
    Example: Using the database-persistent pipeline.

    This demonstrates how to analyze scenarios and automatically
    save results to the database.
    """
    # Initialize pipeline with SQLite database
    pipeline = DatabasePersistentPipeline(
        database_url="sqlite:///threat_hunting.db",
        time_window_minutes=60,
        min_events_for_session=3,
        risk_threshold=0.5,
    )

    # Analyze a scenario (example path)
    telemetry_path = Path("/data/scenarios/credential_stuffing/telemetry.jsonl")

    if telemetry_path.exists():
        # Run analysis and save to database
        results = pipeline.analyze_and_save(
            telemetry_path=telemetry_path,
            scenario_name="credential_stuffing_attack",
            output_dir=Path("/data/reports/credential_stuffing"),
        )

        print(f"Analysis saved with ID: {results['analysis_run_id']}")
        print(f"Detected {results['num_sessions_saved']} sessions")

        # Retrieve high-risk sessions
        high_risk = pipeline.get_high_risk_sessions(min_risk_score=0.7)
        print(f"Found {len(high_risk)} high-risk sessions")

        for session in high_risk:
            print(f"  - {session.session_id}: risk={session.risk_score:.2f}")


def batch_analysis_example():
    """
    Example: Batch analyzing multiple scenarios.

    This demonstrates how to analyze multiple scenarios and
    track them all in the database.
    """
    pipeline = DatabasePersistentPipeline(
        database_url="sqlite:///threat_hunting.db",
    )

    # List of scenarios to analyze
    scenarios = [
        ("credential_stuffing", "/data/scenarios/cred_stuffing/telemetry.jsonl"),
        ("iam_privilege_escalation", "/data/scenarios/iam_privesc/telemetry.jsonl"),
        ("container_escape", "/data/scenarios/container_escape/telemetry.jsonl"),
    ]

    results_summary = []

    for scenario_name, telemetry_file in scenarios:
        telemetry_path = Path(telemetry_file)

        if not telemetry_path.exists():
            logger.warning(f"Skipping {scenario_name}: file not found")
            continue

        try:
            result = pipeline.analyze_and_save(
                telemetry_path=telemetry_path,
                scenario_name=scenario_name,
            )
            results_summary.append(result)
            logger.info(f"Completed analysis of {scenario_name}")

        except Exception as e:
            logger.error(f"Error analyzing {scenario_name}: {e}")

    # Summary
    print("\n" + "=" * 60)
    print("Batch Analysis Summary")
    print("=" * 60)
    for result in results_summary:
        print(
            f"{result['scenario_name']}: "
            f"Run ID {result['analysis_run_id']}, "
            f"{result['num_sessions_saved']} sessions saved"
        )
    print("=" * 60)


if __name__ == "__main__":
    # Run examples
    print("Database Integration Examples")
    print("=" * 60)

    # Note: These examples require actual telemetry files to exist
    # Uncomment to run:
    # example_integration()
    # batch_analysis_example()

    print("\nIntegration examples available in this file.")
    print("Modify the file paths and uncomment to run.")
