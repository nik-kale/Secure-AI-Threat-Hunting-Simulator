"""
Streaming analysis for large telemetry datasets.

This module provides memory-efficient streaming capabilities for analyzing
large telemetry files that cannot be loaded entirely into memory.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Iterator, Optional, Set
from dataclasses import dataclass
from datetime import timedelta
import logging

from .parser import EventParser, NormalizedEvent
from .correlation import EventCorrelator, CorrelationSession

logger = logging.getLogger(__name__)


class StreamingTelemetryLoader:
    """
    Memory-efficient loader for large telemetry files.

    Yields chunks of events instead of loading all events into memory at once.
    """

    def __init__(self, chunk_size: int = 1000):
        """
        Initialize the streaming loader.

        Args:
            chunk_size: Number of events to load per chunk (default: 1000)
        """
        self.chunk_size = chunk_size
        logger.info(f"Initialized StreamingTelemetryLoader with chunk_size={chunk_size}")

    def load_chunks(
        self,
        file_path: Path,
        file_format: str = "jsonl"
    ) -> Iterator[List[Dict[str, Any]]]:
        """
        Load events in chunks from a file.

        Args:
            file_path: Path to telemetry file
            file_format: File format ('jsonl' or 'json')

        Yields:
            Chunks of raw event dictionaries

        Raises:
            FileNotFoundError: If file does not exist
            ValueError: If file format is unsupported
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Telemetry file not found: {file_path}")

        if file_format == "jsonl":
            yield from self._load_chunks_jsonl(file_path)
        elif file_format == "json":
            yield from self._load_chunks_json(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_format}")

    def _load_chunks_jsonl(self, file_path: Path) -> Iterator[List[Dict[str, Any]]]:
        """
        Load JSONL file in chunks (memory-efficient).

        Args:
            file_path: Path to JSONL file

        Yields:
            Chunks of raw event dictionaries
        """
        chunk = []
        total_events = 0
        total_errors = 0

        logger.info(f"Starting streaming load of {file_path}")

        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = json.loads(line)
                        chunk.append(event)
                        total_events += 1

                        # Yield chunk when it reaches the configured size
                        if len(chunk) >= self.chunk_size:
                            logger.debug(f"Yielding chunk of {len(chunk)} events")
                            yield chunk
                            chunk = []

                    except json.JSONDecodeError as e:
                        total_errors += 1
                        logger.warning(
                            f"Failed to parse line {line_num}: {e}. "
                            f"Skipping malformed event."
                        )
                        continue

                    except Exception as e:
                        total_errors += 1
                        logger.error(
                            f"Unexpected error on line {line_num}: {e}. "
                            f"Skipping event."
                        )
                        continue

                # Yield remaining events
                if chunk:
                    logger.debug(f"Yielding final chunk of {len(chunk)} events")
                    yield chunk

        except IOError as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            raise

        logger.info(
            f"Completed streaming load: {total_events} events processed, "
            f"{total_errors} errors encountered"
        )

    def _load_chunks_json(self, file_path: Path) -> Iterator[List[Dict[str, Any]]]:
        """
        Load JSON file in chunks.

        Note: For JSON files, we need to load the entire file first,
        then yield it in chunks. This is less memory-efficient than JSONL
        but necessary for the JSON format.

        Args:
            file_path: Path to JSON file

        Yields:
            Chunks of raw event dictionaries
        """
        logger.info(f"Loading JSON file {file_path} (less memory-efficient)")

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            if isinstance(data, list):
                events = data
            elif isinstance(data, dict) and 'events' in data:
                events = data['events']
            else:
                raise ValueError(
                    "JSON file must contain a list or dict with 'events' key"
                )

            logger.info(f"Loaded {len(events)} events from JSON file")

            # Yield in chunks
            for i in range(0, len(events), self.chunk_size):
                chunk = events[i:i + self.chunk_size]
                logger.debug(f"Yielding chunk {i // self.chunk_size + 1} of {len(chunk)} events")
                yield chunk

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON file {file_path}: {e}")
            raise
        except IOError as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            raise

    def count_events(self, file_path: Path, file_format: str = "jsonl") -> int:
        """
        Count total events in a file without loading all into memory.

        Args:
            file_path: Path to telemetry file
            file_format: File format ('jsonl' or 'json')

        Returns:
            Total number of events in the file
        """
        if file_format == "jsonl":
            count = 0
            with open(file_path, 'r') as f:
                for line in f:
                    if line.strip():
                        count += 1
            return count
        elif file_format == "json":
            with open(file_path, 'r') as f:
                data = json.load(f)

            if isinstance(data, list):
                return len(data)
            elif isinstance(data, dict) and 'events' in data:
                return len(data['events'])
            else:
                raise ValueError("JSON file must contain a list or dict with 'events' key")
        else:
            raise ValueError(f"Unsupported file format: {file_format}")


@dataclass
class StreamingProgress:
    """Tracks progress of streaming analysis."""

    total_events: int = 0
    processed_events: int = 0
    total_chunks: int = 0
    processed_chunks: int = 0
    total_sessions: int = 0
    suspicious_sessions: int = 0

    def percent_complete(self) -> float:
        """Calculate percentage complete."""
        if self.total_events == 0:
            return 0.0
        return (self.processed_events / self.total_events) * 100


def merge_sessions(
    existing_sessions: List[CorrelationSession],
    new_sessions: List[CorrelationSession],
    time_window_minutes: int = 60
) -> List[CorrelationSession]:
    """
    Merge new sessions with existing ones, combining overlapping sessions.

    Sessions are merged if they share the same principal(s) or IP(s)
    and have overlapping or near-overlapping time ranges.

    Args:
        existing_sessions: Previously correlated sessions
        new_sessions: Newly correlated sessions from current chunk
        time_window_minutes: Time window for merging (in minutes)

    Returns:
        Merged list of sessions
    """
    if not existing_sessions:
        return new_sessions

    if not new_sessions:
        return existing_sessions

    time_window = timedelta(minutes=time_window_minutes)
    merged_sessions = list(existing_sessions)

    for new_session in new_sessions:
        merged = False

        # Try to merge with an existing session
        for i, existing_session in enumerate(merged_sessions):
            if _should_merge_sessions(existing_session, new_session, time_window):
                # Merge the sessions
                merged_session = _combine_sessions(existing_session, new_session)
                merged_sessions[i] = merged_session
                merged = True
                logger.debug(
                    f"Merged session {new_session.session_id} into "
                    f"{existing_session.session_id}"
                )
                break

        # If not merged, add as new session
        if not merged:
            merged_sessions.append(new_session)
            logger.debug(f"Added new session {new_session.session_id}")

    return merged_sessions


def _should_merge_sessions(
    session1: CorrelationSession,
    session2: CorrelationSession,
    time_window: timedelta
) -> bool:
    """
    Determine if two sessions should be merged.

    Sessions should be merged if they:
    1. Share at least one principal or source IP
    2. Have time ranges within the correlation window

    Args:
        session1: First session
        session2: Second session
        time_window: Time window for merging

    Returns:
        True if sessions should be merged
    """
    # Check for shared principals or IPs
    shared_principals = session1.principals & session2.principals
    shared_ips = session1.source_ips & session2.source_ips

    if not (shared_principals or shared_ips):
        return False

    # Check time overlap or proximity
    if session1.start_time and session2.start_time:
        # Check if sessions overlap or are within the time window
        time_gap = abs((session1.end_time - session2.start_time).total_seconds())

        # Sessions should merge if they're within the correlation window
        if time_gap <= time_window.total_seconds():
            return True

    return False


def _combine_sessions(
    session1: CorrelationSession,
    session2: CorrelationSession
) -> CorrelationSession:
    """
    Combine two sessions into a single merged session.

    Args:
        session1: First session
        session2: Second session

    Returns:
        Merged session containing all events and metadata
    """
    # Create new merged session
    merged = CorrelationSession(
        session_id=session1.session_id  # Keep first session's ID
    )

    # Combine all events
    all_events = session1.events + session2.events

    # Sort by timestamp
    all_events.sort(key=lambda e: e.timestamp)

    # Add all events to merged session
    for event in all_events:
        merged.add_event(event)

    # Preserve risk score (use higher score)
    merged.risk_score = max(session1.risk_score, session2.risk_score)
    merged.is_malicious = session1.is_malicious or session2.is_malicious

    logger.debug(
        f"Combined sessions: {len(session1.events)} + {len(session2.events)} = "
        f"{len(merged.events)} events"
    )

    return merged
