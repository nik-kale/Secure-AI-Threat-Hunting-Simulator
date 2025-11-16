"""
Example integration of monitoring into the analysis pipeline.

This file demonstrates how to integrate metrics, profiling, and structured
logging into your analysis components.
"""
from pathlib import Path
from typing import List, Dict, Any
import time

# Import monitoring components
from analysis_engine.monitoring import (
    # Metrics
    track_analysis,
    track_session_analysis,
    track_llm_request,
    track_database_query,
    record_event_processed,
    record_ioc_extracted,

    # Profiler
    Profiler,
    profile,
    timed,

    # Logger
    analysis_logger,
    llm_logger,
    database_logger,
    RequestContext,
    log_performance,
    with_correlation_id,
)


# ============================================================================
# Example 1: Tracked Analysis Pipeline
# ============================================================================

class MonitoredThreatHuntingPipeline:
    """
    Example pipeline with comprehensive monitoring integration.
    """

    @track_analysis(scenario="threat_hunting")
    @log_performance()
    def analyze_telemetry_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Analyze telemetry with full monitoring.

        This method demonstrates:
        - Automatic request tracking via decorator
        - Performance logging
        - Event processing metrics
        - Profiling integration
        """
        with Profiler("telemetry_analysis", track_memory=True) as profiler:

            # Load data
            with profiler.time("load_events"):
                events = self._load_events(file_path)

            # Record events processed
            record_event_processed("file", len(events))
            analysis_logger.info(
                "Events loaded",
                event_count=len(events),
                file_size_mb=file_path.stat().st_size / 1024 / 1024
            )

            # Parse events
            with profiler.time("parse_events"):
                parsed_events = self._parse_events(events)

            profiler.snapshot_memory("after_parsing")

            # Correlate events
            with profiler.time("correlate_events"):
                sessions = self._correlate_events(parsed_events)

            analysis_logger.info(
                "Sessions correlated",
                session_count=len(sessions)
            )

            # Analyze sessions
            results = []
            with profiler.time("analyze_sessions"):
                for session in sessions:
                    result = self._analyze_session(session)
                    results.append(result)

            profiler.snapshot_memory("after_analysis")

            # Save profiling report
            profiler.save_report(Path("profiles/telemetry_analysis.json"))

            return {
                "total_events": len(events),
                "total_sessions": len(sessions),
                "results": results
            }

    @timed
    def _load_events(self, file_path: Path) -> List[Dict]:
        """Load events from file."""
        # Your loading logic here
        return []

    @timed
    def _parse_events(self, events: List[Dict]) -> List[Dict]:
        """Parse raw events."""
        # Your parsing logic here
        return events

    @timed
    def _correlate_events(self, events: List[Dict]) -> List[Dict]:
        """Correlate events into sessions."""
        # Your correlation logic here
        return []

    @track_session_analysis
    def _analyze_session(self, session: Dict) -> Dict[str, Any]:
        """
        Analyze a single session with tracking.

        The decorator automatically tracks:
        - Session analysis duration
        - Malicious vs benign sessions
        """
        analysis_logger.info(
            "Analyzing session",
            session_id=session.get("session_id")
        )

        # Your analysis logic
        result = {
            "session_info": session,
            "risk_score": 0.75,  # Example
            "iocs": self._extract_iocs(session)
        }

        return result

    def _extract_iocs(self, session: Dict) -> Dict[str, List]:
        """Extract IOCs and record metrics."""
        iocs = {
            "ips": ["192.168.1.100", "10.0.0.50"],
            "domains": ["malicious.example.com"],
            "hashes": ["abc123def456"]
        }

        # Record IOC extraction metrics
        for ioc_type, ioc_list in iocs.items():
            record_ioc_extracted(ioc_type, len(ioc_list))

        return iocs


# ============================================================================
# Example 2: Monitored LLM Agent
# ============================================================================

class MonitoredNarrativeAgent:
    """
    Example LLM agent with monitoring.
    """

    @track_llm_request(agent="narrative_generator", model="gpt-4")
    @log_performance()
    def generate_narrative(
        self,
        session: Dict,
        context: Dict
    ) -> Dict[str, Any]:
        """
        Generate threat narrative with LLM monitoring.

        Tracks:
        - LLM request count and duration
        - Token usage
        - Success/failure rate
        """
        llm_logger.info(
            "Generating threat narrative",
            session_id=session.get("session_id"),
            event_count=len(session.get("events", []))
        )

        # Simulate LLM call
        time.sleep(0.5)  # Replace with actual LLM call

        # Example response with token usage
        result = {
            "narrative": "Threat narrative here...",
            "usage": {
                "prompt_tokens": 500,
                "completion_tokens": 200,
                "total_tokens": 700
            }
        }

        llm_logger.info(
            "Narrative generated",
            tokens_used=result["usage"]["total_tokens"],
            narrative_length=len(result["narrative"])
        )

        return result


# ============================================================================
# Example 3: Monitored Database Operations
# ============================================================================

class MonitoredSessionStore:
    """
    Example database layer with monitoring.
    """

    @track_database_query(operation="insert", table="sessions")
    def save_session(self, session: Dict) -> str:
        """
        Save session to database with query tracking.

        Tracks:
        - Query count
        - Query duration
        - Success/failure rate
        """
        database_logger.info(
            "Saving session",
            session_id=session.get("session_id")
        )

        # Your database insert logic here
        session_id = "session_123"

        database_logger.info(
            "Session saved",
            session_id=session_id
        )

        return session_id

    @track_database_query(operation="select", table="sessions")
    def get_session(self, session_id: str) -> Dict:
        """Retrieve session from database."""
        database_logger.info(
            "Retrieving session",
            session_id=session_id
        )

        # Your database select logic here
        session = {}

        return session

    @track_database_query(operation="update", table="sessions")
    def update_session(self, session_id: str, updates: Dict) -> bool:
        """Update session in database."""
        database_logger.info(
            "Updating session",
            session_id=session_id,
            update_fields=list(updates.keys())
        )

        # Your database update logic here
        return True


# ============================================================================
# Example 4: Request Handler with Correlation
# ============================================================================

class MonitoredAPIHandler:
    """
    Example API handler with correlation tracking.
    """

    @with_correlation_id
    def handle_analysis_request(
        self,
        file_path: Path,
        options: Dict
    ) -> Dict[str, Any]:
        """
        Handle analysis request with correlation tracking.

        All logs within this request will share the same correlation_id,
        making it easy to trace the entire request flow.
        """
        from analysis_engine.monitoring import api_logger, get_correlation_id

        correlation_id = get_correlation_id()

        api_logger.info(
            "Analysis request received",
            file_path=str(file_path),
            options=options,
            correlation_id=correlation_id
        )

        # Process request (all logs will include correlation_id)
        pipeline = MonitoredThreatHuntingPipeline()
        results = pipeline.analyze_telemetry_file(file_path)

        api_logger.info(
            "Analysis request completed",
            results_count=len(results.get("results", [])),
            correlation_id=correlation_id
        )

        return results


# ============================================================================
# Example 5: Comprehensive Request with Context Manager
# ============================================================================

def process_batch_analysis(files: List[Path]) -> Dict[str, Any]:
    """
    Process multiple files with full request context.

    Uses RequestContext for automatic:
    - Correlation ID generation
    - Start/end logging
    - Performance tracking
    """
    with RequestContext(
        "batch_analysis",
        file_count=len(files)
    ) as ctx:

        pipeline = MonitoredThreatHuntingPipeline()
        results = []

        for i, file_path in enumerate(files, 1):
            analysis_logger.info(
                f"Processing file {i}/{len(files)}",
                file_path=str(file_path)
            )

            result = pipeline.analyze_telemetry_file(file_path)
            results.append(result)

        # Summary
        total_events = sum(r.get("total_events", 0) for r in results)
        total_sessions = sum(r.get("total_sessions", 0) for r in results)

        analysis_logger.info(
            "Batch analysis complete",
            files_processed=len(files),
            total_events=total_events,
            total_sessions=total_sessions
        )

        return {
            "files_processed": len(files),
            "total_events": total_events,
            "total_sessions": total_sessions,
            "results": results
        }


# ============================================================================
# Example 6: Profiled Heavy Computation
# ============================================================================

@profile(name="event_correlation", save_report=True, track_memory=True)
def correlate_large_dataset(events: List[Dict]) -> List[Dict]:
    """
    Profile-intensive correlation algorithm.

    The @profile decorator will:
    - Track execution time
    - Monitor memory usage
    - Save detailed report to profiling_reports/
    - Print summary to console
    """
    analysis_logger.info(
        "Starting correlation",
        event_count=len(events)
    )

    # Your correlation logic here
    sessions = []

    analysis_logger.info(
        "Correlation complete",
        session_count=len(sessions)
    )

    return sessions


# ============================================================================
# Example 7: Manual Profiling for Complex Workflows
# ============================================================================

def complex_analysis_workflow(data: Dict) -> Dict[str, Any]:
    """
    Complex workflow with manual profiling control.
    """
    with Profiler("complex_workflow", track_memory=True) as profiler:

        # Add metadata
        profiler.add_metadata("dataset_size", len(data.get("events", [])))
        profiler.add_metadata("scenario", data.get("scenario"))

        # Stage 1: Data preprocessing
        with profiler.time("preprocessing", stage=1):
            processed_data = preprocess_data(data)
            profiler.snapshot_memory("after_preprocessing")

        # Stage 2: Feature extraction
        with profiler.time("feature_extraction", stage=2):
            features = extract_features(processed_data)
            profiler.snapshot_memory("after_feature_extraction")

        # Stage 3: ML inference
        with profiler.time("ml_inference", stage=3):
            predictions = run_ml_model(features)
            profiler.snapshot_memory("after_inference")

        # Stage 4: Post-processing
        with profiler.time("postprocessing", stage=4):
            results = postprocess_results(predictions)

        # Save detailed report
        report_path = Path("profiles") / f"workflow_{int(time.time())}.json"
        profiler.save_report(report_path)

        # Print summary
        profiler.print_summary()

        return results


def preprocess_data(data: Dict) -> Dict:
    """Preprocess data."""
    return data


def extract_features(data: Dict) -> Dict:
    """Extract features."""
    return {}


def run_ml_model(features: Dict) -> Dict:
    """Run ML model."""
    return {}


def postprocess_results(predictions: Dict) -> Dict:
    """Postprocess results."""
    return {}


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Example 1: Simple file analysis
    pipeline = MonitoredThreatHuntingPipeline()
    results = pipeline.analyze_telemetry_file(Path("telemetry.jsonl"))

    # Example 2: Batch processing
    files = [Path(f"file{i}.jsonl") for i in range(5)]
    batch_results = process_batch_analysis(files)

    # Example 3: LLM agent
    agent = MonitoredNarrativeAgent()
    narrative = agent.generate_narrative(
        session={"session_id": "123", "events": []},
        context={}
    )

    # Example 4: Database operations
    store = MonitoredSessionStore()
    session_id = store.save_session({"session_id": "123", "data": {}})
    session = store.get_session(session_id)

    print("Monitoring examples completed!")
    print("Check http://localhost:8000/metrics for Prometheus metrics")
    print("Check http://localhost:8000/stats for JSON statistics")
