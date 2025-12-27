"""PDF report generator using ReportLab."""
from pathlib import Path
from typing import Dict, Any
from datetime import datetime


class PDFReportGenerator:
    """Generate PDF reports from analysis results."""
    
    def __init__(self, template_dir: Path = None):
        """Initialize PDF generator."""
        self.template_dir = template_dir or Path(__file__).parent / "templates"
    
    def generate(self, analysis_result: Dict[str, Any], output_path: Path) -> Path:
        """
        Generate PDF report.
        
        Args:
            analysis_result: Analysis results dictionary
            output_path: Output file path
            
        Returns:
            Path to generated PDF
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            
            doc = SimpleDocTemplate(str(output_path), pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title = Paragraph(
                f"<b>Threat Analysis Report</b><br/>{datetime.now().strftime('%Y-%m-%d %H:%M')}",
                styles['Title']
            )
            story.append(title)
            story.append(Spacer(1, 0.5 * inch))
            
            # Summary section
            summary_data = [
                ["Metric", "Value"],
                ["Total Events", str(analysis_result.get("total_events", 0))],
                ["Sessions Detected", str(analysis_result.get("sessions", 0))],
                ["MITRE Techniques", str(len(analysis_result.get("mitre_techniques", [])))],
            ]
            summary_table = Table(summary_data)
            story.append(summary_table)
            
            # Build PDF
            doc.build(story)
            return output_path
            
        except ImportError:
            # Fallback: create simple text file if reportlab not installed
            with open(output_path.with_suffix('.txt'), 'w') as f:
                f.write("PDF generation requires 'reportlab' package\n")
                f.write(f"Analysis results:\n{analysis_result}\n")
            return output_path.with_suffix('.txt')

