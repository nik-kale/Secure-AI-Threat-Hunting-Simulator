"""HTML report generator."""
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
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
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
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
        <tr><td>Total Events</td><td>{analysis_result.get('total_events', 0)}</td></tr>
        <tr><td>Sessions Detected</td><td>{analysis_result.get('sessions', 0)}</td></tr>
        <tr><td>MITRE Techniques</td><td>{len(analysis_result.get('mitre_techniques', []))}</td></tr>
    </table>
    
    <h2>Details</h2>
    <pre>{json.dumps(analysis_result, indent=2)}</pre>
</body>
</html>
"""
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return output_path

