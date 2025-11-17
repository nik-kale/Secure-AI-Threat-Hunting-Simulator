"""
Main analysis pipeline orchestrator.
"""
from pathlib import Path
from typing import Any, Dict, Optional
import logging
import os
import time

from .core import (
    TelemetryLoader,
    EventParser,
    EventCorrelator,
    KillChainMapper,
    MitreMapper,
    StreamingTelemetryLoader,
    StreamingProgress,
    merge_sessions,
    GraphCorrelator,
    GRAPH_CORRELATION_AVAILABLE,
)
from .agents import (
    IocExtractorAgent,
    ThreatNarrativeAgent,
    ResponsePlannerAgent,
)
from .reports import JsonReporter, MarkdownReporter

# Optional database persistence
try:
    from .database import (
        DatabaseConfig,
        DatabaseManager,
        AnalysisRepository,
        SessionRepository,
        IOCRepository,
    )
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False
    logger.warning("Database module not available. Analysis results will not be persisted.")

# Optional LLM integration
try:
    from .llm import get_llm_provider, LLMProvider
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.info("LLM integration not available. Using template-based analysis.")

# Optional cache integration
try:
    from .cache import get_cache, CacheNamespace
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
    logger.info("Cache module not available. Running without caching.")

# Optional threat intelligence integration
try:
    from .threat_intel import IOCEnricher, create_enricher_from_config
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    logger.info("Threat intelligence integration not available.")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# File size threshold for automatic streaming (50 MB)
STREAMING_THRESHOLD_BYTES = 50 * 1024 * 1024


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
        risk_threshold: float = 0.5,
        enable_graph_analysis: bool = True,
        enable_database: bool = None,
        database_url: Optional[str] = None,
        llm_provider_type: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
        enable_threat_intel: bool = None,
        threat_intel_config: Optional[Any] = None
    ):
        """
        Initialize the analysis pipeline.

        Args:
            time_window_minutes: Correlation time window
            min_events_for_session: Minimum events to form a session
            risk_threshold: Risk score threshold for identifying threats
            enable_graph_analysis: Enable graph-based correlation (requires networkx)
            enable_database: Enable database persistence (auto-detects if None)
            database_url: Database connection URL (uses env var DB_CONNECTION_STRING if None)
            llm_provider_type: LLM provider to use ('openai', 'anthropic', or None)
            llm_api_key: API key for LLM provider (if None, uses env var)
            llm_model: Model name to use (if None, uses provider default)
            enable_threat_intel: Enable threat intelligence enrichment (auto-detects if None)
            threat_intel_config: Config object with threat intel settings
        """
        self.loader = TelemetryLoader()
        self.parser = EventParser()
        self.correlator = EventCorrelator(
            time_window_minutes=time_window_minutes,
            min_events_for_session=min_events_for_session
        )
        self.kill_chain_mapper = KillChainMapper()
        self.mitre_mapper = MitreMapper()

        # Store configuration for database persistence
        self.time_window_minutes = time_window_minutes
        self.min_events_for_session = min_events_for_session
        self.risk_threshold = risk_threshold

        # Initialize LLM provider if configured
        self.llm_provider = None
        if llm_provider_type and llm_provider_type.lower() not in ["none", ""]:
            if LLM_AVAILABLE:
                try:
                    self.llm_provider = get_llm_provider(
                        provider_type=llm_provider_type,
                        api_key=llm_api_key,
                        model=llm_model
                    )
                    logger.info(f"LLM provider initialized: {llm_provider_type}")
                except Exception as e:
                    logger.warning(f"Failed to initialize LLM provider: {e}. Using template-based analysis.")
                    self.llm_provider = None
            else:
                logger.warning("LLM integration requested but not available. Using template-based analysis.")

        # Initialize threat intelligence enricher if configured
        self.threat_intel_enricher = None
        if enable_threat_intel is None:
            # Auto-detect: enable if config provided and module available
            enable_threat_intel = (
                THREAT_INTEL_AVAILABLE and
                threat_intel_config is not None and
                getattr(threat_intel_config, 'enable_threat_intel', False)
            )

        if enable_threat_intel and THREAT_INTEL_AVAILABLE:
            try:
                if threat_intel_config:
                    self.threat_intel_enricher = create_enricher_from_config(threat_intel_config)
                    logger.info("Threat intelligence enrichment enabled")
                else:
                    logger.warning("Threat intelligence requested but no config provided")
            except Exception as e:
                logger.warning(f"Failed to initialize threat intelligence: {e}")
                self.threat_intel_enricher = None

        # Initialize agents with optional LLM and threat intel
        self.ioc_extractor = IocExtractorAgent(
            llm_provider=self.llm_provider,
            use_llm=self.llm_provider is not None,
            threat_intel_enricher=self.threat_intel_enricher,
            enable_enrichment=self.threat_intel_enricher is not None
        )
        self.narrative_generator = ThreatNarrativeAgent(
            llm_provider=self.llm_provider,
            use_llm=self.llm_provider is not None
        )
        self.response_planner = ResponsePlannerAgent(
            llm_provider=self.llm_provider,
            use_llm=self.llm_provider is not None
        )

        # Initialize graph correlator if available and enabled
        self.enable_graph_analysis = enable_graph_analysis and GRAPH_CORRELATION_AVAILABLE
        if self.enable_graph_analysis:
            self.graph_correlator = GraphCorrelator()
            logger.info("Graph-based correlation enabled")
        else:
            self.graph_correlator = None
            if enable_graph_analysis and not GRAPH_CORRELATION_AVAILABLE:
                logger.warning(
                    "Graph analysis requested but networkx not available. "
                    "Install with: pip install networkx>=3.0 python-louvain"
                )

        # Initialize database persistence if available and enabled
        if enable_database is None:
            enable_database = DATABASE_AVAILABLE and os.getenv("DB_CONNECTION_STRING") is not None

        self.enable_database = enable_database and DATABASE_AVAILABLE
        self.db_manager = None

        if self.enable_database:
            try:
                # Get database URL from parameter or environment
                db_url = database_url or os.getenv(
                    "DB_CONNECTION_STRING",
                    "sqlite:///./data/threat_hunting.db"
                )

                # Initialize database manager
                config = DatabaseConfig.from_url(db_url)
                self.db_manager = DatabaseManager(config)

                # Create tables if they don't exist
                from .database.models import Base
                Base.metadata.create_all(self.db_manager.engine)

                logger.info(f"Database persistence enabled: {db_url}")
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                self.enable_database = False
                self.db_manager = None

    def analyze_telemetry_file(
        self,
        telemetry_path: Path,
        output_dir: Optional[Path] = None,
        force_streaming: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze telemetry from a file.

        Automatically uses streaming mode for large files (>50MB) to prevent
        memory issues. Streaming can also be forced via the force_streaming parameter.

        Args:
            telemetry_path: Path to telemetry file (JSONL or JSON)
            output_dir: Optional directory for output reports
            force_streaming: Force streaming mode even for small files

        Returns:
            Complete analysis results
        """
        logger.info(f"Starting analysis of {telemetry_path}")

        # Check if we should use streaming
        use_streaming = force_streaming or self._should_use_streaming(telemetry_path)

        if use_streaming:
            logger.info(
                f"Using streaming mode for large file "
                f"({self._get_file_size_mb(telemetry_path):.2f} MB)"
            )
            return self._analyze_with_streaming(telemetry_path, output_dir)

        # Standard in-memory analysis for smaller files
        logger.info("Using standard in-memory analysis")

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

        # Save to database if enabled
        if self.enable_database and self.db_manager:
            try:
                self._save_to_database(
                    scenario_name=telemetry_path.stem,
                    telemetry_file_path=str(telemetry_path),
                    summary=summary,
                    analysis_results=analysis_results
                )
            except Exception as e:
                logger.error(f"Failed to save analysis to database: {e}")

        logger.info("Analysis complete")
        return summary

    def _should_use_streaming(self, file_path: Path) -> bool:
        """
        Determine if streaming mode should be used based on file size.

        Args:
            file_path: Path to telemetry file

        Returns:
            True if streaming should be used
        """
        try:
            file_size = os.path.getsize(file_path)
            should_stream = file_size > STREAMING_THRESHOLD_BYTES

            if should_stream:
                size_mb = file_size / (1024 * 1024)
                logger.info(
                    f"File size ({size_mb:.2f} MB) exceeds threshold "
                    f"({STREAMING_THRESHOLD_BYTES / (1024 * 1024):.0f} MB). "
                    f"Using streaming mode."
                )

            return should_stream

        except OSError as e:
            logger.warning(f"Could not check file size: {e}. Using standard mode.")
            return False

    def _get_file_size_mb(self, file_path: Path) -> float:
        """
        Get file size in megabytes.

        Args:
            file_path: Path to file

        Returns:
            File size in MB
        """
        try:
            return os.path.getsize(file_path) / (1024 * 1024)
        except OSError:
            return 0.0

    def _analyze_with_streaming(
        self,
        telemetry_path: Path,
        output_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Analyze telemetry using streaming mode.

        Args:
            telemetry_path: Path to telemetry file
            output_dir: Optional directory for output reports

        Returns:
            Complete analysis results
        """
        # Create streaming pipeline with same configuration
        streaming_pipeline = StreamingPipeline(
            time_window_minutes=self.correlator.time_window.total_seconds() / 60,
            min_events_for_session=self.correlator.min_events,
            risk_threshold=self.risk_threshold,
            chunk_size=1000
        )

        # Define progress callback
        def log_progress(progress):
            logger.info(
                f"Progress: {progress.processed_events}/{progress.total_events} events "
                f"({progress.percent_complete():.1f}%), "
                f"{progress.total_sessions} sessions, "
                f"{progress.suspicious_sessions} suspicious"
            )

        # Run streaming analysis
        return streaming_pipeline.analyze_telemetry_stream(
            telemetry_path,
            output_dir,
            progress_callback=log_progress
        )

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

        # Graph-based analysis (if enabled)
        graph_data = None
        if self.enable_graph_analysis:
            graph_data = self.analyze_session_graph(session)

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

        # Add graph data if available
        if graph_data:
            results["graph_analysis"] = graph_data

        return results

    def analyze_session_graph(self, session) -> Dict[str, Any]:
        """
        Perform graph-based analysis on a session.

        Args:
            session: CorrelationSession to analyze

        Returns:
            Graph analysis results
        """
        if not self.enable_graph_analysis:
            return None

        logger.info(f"Performing graph analysis on session {session.session_id}")

        try:
            # Build attack graph from session events
            self.graph_correlator.build_attack_graph(session.events)

            # Get graph summary
            graph_summary = self.graph_correlator.generate_graph_summary()

            # Detect attack campaigns
            campaigns = self.graph_correlator.detect_attack_campaigns(
                min_campaign_size=2
            )

            # Find pivot points
            pivot_points = self.graph_correlator.find_pivot_points(
                top_n=5,
                min_degree=2
            )

            # Identify lateral movement
            lateral_movements = self.graph_correlator.identify_lateral_movement(
                min_hops=2,
                time_window_minutes=60
            )

            # Compile graph analysis results
            graph_data = {
                "graph_summary": graph_summary,
                "attack_campaigns": [c.to_dict() for c in campaigns],
                "pivot_points": [p.to_dict() for p in pivot_points],
                "lateral_movements": [m.to_dict() for m in lateral_movements],
            }

            logger.info(
                f"Graph analysis complete: {len(campaigns)} campaigns, "
                f"{len(pivot_points)} pivot points, "
                f"{len(lateral_movements)} lateral movements"
            )

            return graph_data

        except Exception as e:
            logger.error(f"Graph analysis failed: {e}")
            return {
                "error": str(e),
                "graph_summary": {"nodes": 0, "edges": 0}
            }

    def _save_to_database(
        self,
        scenario_name: str,
        telemetry_file_path: str,
        summary: Dict[str, Any],
        analysis_results: list,
        analysis_duration_seconds: Optional[float] = None
    ) -> None:
        """
        Save analysis results to database.

        Args:
            scenario_name: Name of the scenario
            telemetry_file_path: Path to telemetry file
            summary: Analysis summary dictionary
            analysis_results: List of analyzed sessions
            analysis_duration_seconds: Duration of analysis in seconds
        """
        if not self.enable_database or not self.db_manager:
            return

        try:
            with self.db_manager.session_scope() as session:
                # Create repositories
                analysis_repo = AnalysisRepository(session)
                session_repo = SessionRepository(session)
                ioc_repo = IOCRepository(session)

                # Save analysis run
                analysis_run = analysis_repo.save_analysis_run(
                    scenario_name=scenario_name,
                    num_events=summary.get("total_events", 0),
                    num_sessions=summary.get("total_sessions", 0),
                    num_suspicious_sessions=summary.get("suspicious_sessions", 0),
                    results=summary,
                    time_window_minutes=self.time_window_minutes,
                    min_events_for_session=self.min_events_for_session,
                    risk_threshold=self.risk_threshold,
                    telemetry_file_path=telemetry_file_path,
                    analysis_duration_seconds=analysis_duration_seconds,
                )

                # Save detected sessions
                for session_data in analysis_results:
                    detected_session = session_repo.save_session(
                        analysis_run_id=analysis_run.id,
                        session_id=session_data.get("session_id", ""),
                        principal=session_data.get("principal", ""),
                        event_count=session_data.get("event_count", 0),
                        risk_score=session_data.get("risk_score", 0.0),
                        start_time=session_data.get("start_time"),
                        end_time=session_data.get("end_time"),
                        is_malicious=session_data.get("risk_score", 0.0) >= self.risk_threshold,
                        mitre_techniques=session_data.get("mitre_techniques", []),
                        kill_chain_stages=session_data.get("kill_chain_stages", []),
                        session_data=session_data,
                    )

                    # Save IOCs for this session
                    iocs_data = session_data.get("iocs", {})
                    if iocs_data:
                        # Save IP addresses
                        for ip in iocs_data.get("ip_addresses", []):
                            ioc_repo.save_ioc(
                                analysis_run_id=analysis_run.id,
                                detected_session_id=detected_session.id,
                                ioc_type="ip_address",
                                value=ip.get("ip", ""),
                                severity=ip.get("severity", "medium"),
                                description=f"IP address from {ip.get('context', 'unknown context')}",
                            )

                        # Save principals
                        for principal in iocs_data.get("principals", []):
                            ioc_repo.save_ioc(
                                analysis_run_id=analysis_run.id,
                                detected_session_id=detected_session.id,
                                ioc_type="principal",
                                value=principal.get("principal", ""),
                                severity=principal.get("severity", "medium"),
                                description="Suspicious principal",
                            )

                        # Save commands
                        for cmd in iocs_data.get("commands", []):
                            ioc_repo.save_ioc(
                                analysis_run_id=analysis_run.id,
                                detected_session_id=detected_session.id,
                                ioc_type="command",
                                value=cmd.get("command", ""),
                                severity=cmd.get("severity", "medium"),
                                description=f"Suspicious command",
                            )

                logger.info(
                    f"Saved analysis run {analysis_run.id} to database: "
                    f"{summary.get('suspicious_sessions', 0)} suspicious sessions"
                )

        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            raise

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

        # Graph export (if graph analysis was performed)
        if self.enable_graph_analysis and "graph_analysis" in analysis_results:
            try:
                graph_path = output_dir / "attack_graph.graphml"
                self.graph_correlator.export_to_graphml(graph_path)
                logger.info(f"Attack graph exported to {graph_path}")
            except Exception as e:
                logger.error(f"Failed to export graph: {e}")

        logger.info(f"Reports written to {output_dir}")


class StreamingPipeline(ThreatHuntingPipeline):
    """
    Streaming analysis pipeline for large telemetry datasets.

    Extends ThreatHuntingPipeline with streaming capabilities for processing
    large files that don't fit in memory.
    """

    def __init__(
        self,
        time_window_minutes: int = 60,
        min_events_for_session: int = 3,
        risk_threshold: float = 0.5,
        chunk_size: int = 1000,
        enable_graph_analysis: bool = True
    ):
        """
        Initialize the streaming pipeline.

        Args:
            time_window_minutes: Correlation time window
            min_events_for_session: Minimum events to form a session
            risk_threshold: Risk score threshold for identifying threats
            chunk_size: Number of events to process per chunk
            enable_graph_analysis: Enable graph-based correlation (requires networkx)
        """
        super().__init__(
            time_window_minutes=time_window_minutes,
            min_events_for_session=min_events_for_session,
            risk_threshold=risk_threshold,
            enable_graph_analysis=enable_graph_analysis
        )

        self.streaming_loader = StreamingTelemetryLoader(chunk_size=chunk_size)
        self.chunk_size = chunk_size
        logger.info(f"Initialized StreamingPipeline with chunk_size={chunk_size}")

    def analyze_telemetry_stream(
        self,
        telemetry_path: Path,
        output_dir: Optional[Path] = None,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Analyze telemetry using streaming to handle large files.

        Args:
            telemetry_path: Path to telemetry file (JSONL or JSON)
            output_dir: Optional directory for output reports
            progress_callback: Optional callback for progress updates

        Returns:
            Complete analysis results
        """
        logger.info(f"Starting streaming analysis of {telemetry_path}")

        # Determine file format
        file_format = "jsonl" if telemetry_path.suffix == ".jsonl" else "json"

        # Count total events for progress tracking
        try:
            total_events = self.streaming_loader.count_events(
                telemetry_path,
                file_format
            )
            logger.info(f"File contains {total_events} total events")
        except Exception as e:
            logger.warning(f"Could not count events: {e}. Progress tracking may be limited.")
            total_events = 0

        # Initialize progress tracking
        progress = StreamingProgress(total_events=total_events)

        # Process chunks
        from .core.correlation import CorrelationSession
        all_sessions = []
        chunk_num = 0

        try:
            for chunk in self.streaming_loader.load_chunks(telemetry_path, file_format):
                chunk_num += 1
                progress.total_chunks = chunk_num
                progress.processed_chunks = chunk_num

                logger.info(f"Processing chunk {chunk_num} ({len(chunk)} events)")

                # Parse events in this chunk
                normalized_events = self.parser.parse_events(chunk)
                progress.processed_events += len(normalized_events)

                # Correlate events in this chunk
                chunk_sessions = self.correlator.correlate_multi_criteria(normalized_events)

                # Merge with existing sessions
                all_sessions = merge_sessions(
                    all_sessions,
                    chunk_sessions,
                    time_window_minutes=int(self.correlator.time_window.total_seconds() / 60)
                )
                progress.total_sessions = len(all_sessions)

                # Report progress
                if progress_callback:
                    progress_callback(progress)

                logger.info(
                    f"Chunk {chunk_num} complete: "
                    f"{progress.processed_events}/{progress.total_events} events processed "
                    f"({progress.percent_complete():.1f}%), "
                    f"{len(all_sessions)} total sessions"
                )

        except Exception as e:
            logger.error(f"Error during streaming analysis: {e}")
            raise

        logger.info(f"Streaming load complete: {len(all_sessions)} total sessions correlated")

        # Identify suspicious sessions
        suspicious_sessions = self.correlator.identify_suspicious_sessions(
            all_sessions,
            threshold=self.risk_threshold
        )
        progress.suspicious_sessions = len(suspicious_sessions)
        logger.info(f"Identified {len(suspicious_sessions)} suspicious sessions")

        # Analyze each suspicious session
        analysis_results = []

        for i, session in enumerate(suspicious_sessions, 1):
            logger.info(f"Analyzing suspicious session {i}/{len(suspicious_sessions)}")
            session_analysis = self.analyze_session(session)
            analysis_results.append(session_analysis)

        # Generate summary report
        summary = {
            "total_events": progress.processed_events,
            "total_sessions": len(all_sessions),
            "suspicious_sessions": len(suspicious_sessions),
            "sessions": analysis_results,
            "streaming_stats": {
                "chunks_processed": progress.processed_chunks,
                "chunk_size": self.chunk_size,
            }
        }

        # Write reports if output directory specified
        if output_dir and analysis_results:
            self.write_reports(analysis_results[0], output_dir)

        # Save to database if enabled
        if self.enable_database and self.db_manager:
            try:
                self._save_to_database(
                    scenario_name=telemetry_path.stem,
                    telemetry_file_path=str(telemetry_path),
                    summary=summary,
                    analysis_results=analysis_results
                )
            except Exception as e:
                logger.error(f"Failed to save streaming analysis to database: {e}")

        logger.info("Streaming analysis complete")
        return summary


def analyze_scenario(
    telemetry_path: Path,
    output_dir: Path,
    time_window: int = 60,
    min_events: int = 3,
    force_streaming: bool = False
) -> Dict[str, Any]:
    """
    Convenience function to analyze a scenario.

    Args:
        telemetry_path: Path to telemetry file
        output_dir: Output directory for reports
        time_window: Correlation time window in minutes
        min_events: Minimum events for session
        force_streaming: Force streaming mode even for small files

    Returns:
        Analysis results
    """
    pipeline = ThreatHuntingPipeline(
        time_window_minutes=time_window,
        min_events_for_session=min_events
    )

    return pipeline.analyze_telemetry_file(
        telemetry_path,
        output_dir,
        force_streaming=force_streaming
    )
