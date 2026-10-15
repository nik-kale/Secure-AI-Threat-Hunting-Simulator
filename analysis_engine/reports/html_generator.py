"""HTML report generator."""

from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import html
import json


class HTMLReportGenerator:
    """Generate HTML reports from analysis results."""

    def __init__(self, template_dir: Path = None):
        """Initialize HTML generator."""
        self.template_dir = template_dir or Path(__file__).parent / "templates"

    def generate(self, analysis_result: Dict[str, Any], output_path: Path) -> Path:
        """
        Generate HTML report.

        Args:
            analysis_result: Analysis results dictionary
            output_path: Output file path

        Returns:
            Path to generated HTML
        """

        # Telemetry values (user agents, commands, principals) are attacker
        # controlled, so everything interpolated into the page is escaped.
        def esc(value: Any) -> str:
            return html.escape(str(value), quote=True)

        sessions = analysis_result.get("sessions", 0)
        sessions_detected = analysis_result.get(
            "suspicious_sessions",
            len(sessions) if isinstance(sessions, list) else sessions,
        )

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Threat Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        .metric {{ font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Threat Analysis Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Events</td><td>{esc(analysis_result.get('total_events', 0))}</td></tr>
        <tr><td>Sessions Detected</td><td>{esc(sessions_detected)}</td></tr>
        <tr><td>MITRE Techniques</td><td>{len(analysis_result.get('mitre_techniques', []))}</td></tr>
    </table>
    
    <h2>Details</h2>
    <pre>{esc(json.dumps(analysis_result, indent=2, default=str))}</pre>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path
