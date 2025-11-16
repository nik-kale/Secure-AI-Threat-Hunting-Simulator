"""
Telemetry and configuration loader.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class TelemetryLoader:
    """Loads telemetry events and configuration files."""

    @staticmethod
    def load_events_jsonl(file_path: Path) -> List[Dict[str, Any]]:
        """
        Load events from JSONL file.

        Args:
            file_path: Path to JSONL file

        Returns:
            List of event dictionaries
        """
        events = []

        if not file_path.exists():
            raise FileNotFoundError(f"Telemetry file not found: {file_path}")

        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                    events.append(event)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse line {line_num}: {e}")
                    continue

        logger.info(f"Loaded {len(events)} events from {file_path}")
        return events

    @staticmethod
    def load_events_json(file_path: Path) -> List[Dict[str, Any]]:
        """
        Load events from JSON file.

        Args:
            file_path: Path to JSON file

        Returns:
            List of event dictionaries
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Telemetry file not found: {file_path}")

        with open(file_path, 'r') as f:
            data = json.load(f)

        if isinstance(data, list):
            events = data
        elif isinstance(data, dict) and 'events' in data:
            events = data['events']
        else:
            raise ValueError("JSON file must contain a list or dict with 'events' key")

        logger.info(f"Loaded {len(events)} events from {file_path}")
        return events

    @staticmethod
    def load_topology(file_path: Path) -> Dict[str, Any]:
        """
        Load cloud topology configuration.

        Args:
            file_path: Path to topology JSON file

        Returns:
            Topology dictionary
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Topology file not found: {file_path}")

        with open(file_path, 'r') as f:
            topology = json.load(f)

        logger.info(f"Loaded topology: {topology.get('name', 'unknown')}")
        return topology

    @staticmethod
    def load_scenario_metadata(scenario_dir: Path) -> Optional[Dict[str, Any]]:
        """
        Load scenario metadata if available.

        Args:
            scenario_dir: Directory containing scenario files

        Returns:
            Scenario metadata or None
        """
        metadata_path = scenario_dir / "metadata.json"

        if not metadata_path.exists():
            return None

        with open(metadata_path, 'r') as f:
            metadata = json.load(f)

        return metadata

    @classmethod
    def load_scenario(
        cls,
        scenario_dir: Path,
        telemetry_filename: str = "telemetry.jsonl"
    ) -> Dict[str, Any]:
        """
        Load a complete scenario including telemetry and metadata.

        Args:
            scenario_dir: Directory containing scenario files
            telemetry_filename: Name of telemetry file

        Returns:
            Dictionary with 'events' and optional 'metadata'
        """
        telemetry_path = scenario_dir / telemetry_filename

        # Try JSONL first, then JSON
        if telemetry_path.exists():
            events = cls.load_events_jsonl(telemetry_path)
        else:
            telemetry_path = scenario_dir / "telemetry.json"
            events = cls.load_events_json(telemetry_path)

        metadata = cls.load_scenario_metadata(scenario_dir)

        return {
            "events": events,
            "metadata": metadata,
            "scenario_dir": str(scenario_dir),
        }
