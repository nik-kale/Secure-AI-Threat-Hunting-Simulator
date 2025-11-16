"""
Main analysis pipeline orchestrator.
"""
from pathlib import Path
from typing import Any, Dict, Optional
import logging

from .core import (
    TelemetryLoader,
    EventParser,
    EventCorrelator,
    KillChainMapper,
    MitreMapper,
)
from .agents import (
    IocExtractorAgent,
    ThreatNarrativeAgent,
    ResponsePlannerAgent,
)
from .reports import JsonReporter, MarkdownReporter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatHuntingPipeline:
    """
    Main pipeline for threat hunting analysis.

    Orchestrates all analysis components from telemetry loading through
    report generation.
    """

    def __init__(
        self,
        time_window_minutes: int = 60,
        min_events_for_session: int = 3,
        risk_threshold: float = 0.5
    ):
        """
        Initialize the analysis pipeline.

        Args:
            time_window_minutes: Correlation time window
            min_events_for_session: Minimum events to form a session
            risk_threshold: Risk score threshold for identifying threats
        """
        self.loader = TelemetryLoader()
        self.parser = EventParser()
        self.correlator = EventCorrelator(
            time_window_minutes=time_window_minutes,
            min_events_for_session=min_events_for_session
        )
        self.kill_chain_mapper = KillChainMapper()
        self.mitre_mapper = MitreMapper()

        self.ioc_extractor = IocExtractorAgent()
        self.narrative_generator = ThreatNarrativeAgent()
        self.response_planner = ResponsePlannerAgent()

        self.risk_threshold = risk_threshold

    def analyze_telemetry_file(
        self,
        telemetry_path: Path,
        output_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Analyze telemetry from a file.

        Args:
            telemetry_path: Path to telemetry file (JSONL or JSON)
            output_dir: Optional directory for output reports

        Returns:
            Complete analysis results
        """
        logger.info(f"Starting analysis of {telemetry_path}")

        # Step 1: Load and parse events
        if telemetry_path.suffix == ".jsonl":
            raw_events = self.loader.load_events_jsonl(telemetry_path)
        else:
            raw_events = self.loader.load_events_json(telemetry_path)

        normalized_events = self.parser.parse_events(raw_events)
        logger.info(f"Parsed {len(normalized_events)} events")

        # Step 2: Correlate events into sessions
        sessions = self.correlator.correlate_multi_criteria(normalized_events)
        logger.info(f"Correlated {len(sessions)} sessions")

        # Step 3: Identify suspicious sessions
        suspicious_sessions = self.correlator.identify_suspicious_sessions(
            sessions,
            threshold=self.risk_threshold
        )
        logger.info(f"Identified {len(suspicious_sessions)} suspicious sessions")

        # Step 4: Analyze each suspicious session
        analysis_results = []

        for session in suspicious_sessions:
            session_analysis = self.analyze_session(session)
            analysis_results.append(session_analysis)

        # Generate summary report
        summary = {
            "total_events": len(normalized_events),
            "total_sessions": len(sessions),
            "suspicious_sessions": len(suspicious_sessions),
            "sessions": analysis_results,
        }

        # Write reports if output directory specified
        if output_dir and analysis_results:
            self.write_reports(analysis_results[0], output_dir)

        logger.info("Analysis complete")
        return summary

    def analyze_session(self, session) -> Dict[str, Any]:
        """
        Perform deep analysis on a single session.

        Args:
            session: CorrelationSession to analyze

        Returns:
            Complete analysis results for the session
        """
        logger.info(f"Analyzing session {session.session_id}")

        # Kill chain analysis
        kill_chain_data = self.kill_chain_mapper.map_session(session)

        # MITRE ATT&CK mapping
        mitre_data = self.mitre_mapper.map_session(session)

        # IOC extraction
        ioc_data = self.ioc_extractor.extract_from_session(session)

        # Threat narrative generation
        narrative_data = self.narrative_generator.generate_narrative(
            session=session,
            kill_chain_data=kill_chain_data,
            mitre_data=mitre_data,
            ioc_data=ioc_data
        )

        # Response planning
        response_plan = self.response_planner.generate_response_plan(
            session=session,
            mitre_data=mitre_data,
            ioc_data=ioc_data,
            narrative_data=narrative_data
        )

        # Compile results
        results = {
            "session_info": session.to_dict(),
            "kill_chain": kill_chain_data,
            "mitre": mitre_data,
            "iocs": ioc_data,
            "narrative": narrative_data,
            "response_plan": response_plan,
        }

        return results

    def write_reports(
        self,
        analysis_results: Dict[str, Any],
        output_dir: Path
    ) -> None:
        """
        Write analysis reports to files.

        Args:
            analysis_results: Complete analysis results
            output_dir: Output directory
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # JSON report
        json_path = output_dir / "analysis_report.json"
        JsonReporter.generate_report(analysis_results, json_path)

        # Markdown report
        md_path = output_dir / "analysis_report.md"
        MarkdownReporter.generate_report(analysis_results, md_path)

        # IOC report
        ioc_path = output_dir / "iocs.json"
        JsonReporter.generate_ioc_report(analysis_results.get("iocs", {}), ioc_path)

        logger.info(f"Reports written to {output_dir}")


def analyze_scenario(
    telemetry_path: Path,
    output_dir: Path,
    time_window: int = 60,
    min_events: int = 3
) -> Dict[str, Any]:
    """
    Convenience function to analyze a scenario.

    Args:
        telemetry_path: Path to telemetry file
        output_dir: Output directory for reports
        time_window: Correlation time window in minutes
        min_events: Minimum events for session

    Returns:
        Analysis results
    """
    pipeline = ThreatHuntingPipeline(
        time_window_minutes=time_window,
        min_events_for_session=min_events
    )

    return pipeline.analyze_telemetry_file(telemetry_path, output_dir)
