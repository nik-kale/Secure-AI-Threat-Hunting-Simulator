"""JSON report writers for analysis results."""
import json
from pathlib import Path
from typing import Any, Dict, List


class JsonReporter:
    """Write analysis results and IOCs as JSON files."""

    @staticmethod
    def generate_report(analysis_results: Dict[str, Any], output_path: Path) -> Path:
        """
        Write the complete analysis results to a JSON file.

        Args:
            analysis_results: Analysis summary returned by the pipeline
            output_path: Destination file

        Returns:
            Path to the written file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(analysis_results, f, indent=2, default=str)
        return output_path

    @staticmethod
    def merge_iocs(sessions: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Merge the IOCs of every analysed session, de-duplicated per IOC type.

        Args:
            sessions: Per-session analysis results, each holding an ``iocs`` report

        Returns:
            Mapping of IOC type to its sorted unique values
        """
        merged: Dict[str, set] = {}
        for session in sessions:
            iocs = (session.get("iocs") or {}).get("iocs") or {}
            for ioc_type, values in iocs.items():
                merged.setdefault(ioc_type, set()).update(str(v) for v in values)
        return {ioc_type: sorted(values) for ioc_type, values in sorted(merged.items())}

    @staticmethod
    def generate_ioc_report(iocs: Dict[str, List[str]], output_path: Path) -> Path:
        """
        Write IOCs to a JSON file.

        Args:
            iocs: Mapping of IOC type to values
            output_path: Destination file

        Returns:
            Path to the written file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "total_iocs": sum(len(values) for values in iocs.values()),
            "iocs": iocs,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        return output_path
