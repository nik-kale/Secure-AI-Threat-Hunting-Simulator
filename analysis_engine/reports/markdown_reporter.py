"""Markdown report writer for analysis results."""
from pathlib import Path
from typing import Any, Dict, List


def _code(value: Any) -> str:
    """Render a telemetry value as inline code so it cannot inject Markdown."""
    text = str(value).replace("`", "'").replace("\n", " ").replace("\r", " ")
    return f"`{text}`"


class MarkdownReporter:
    """Write a human-readable Markdown summary of analysis results."""

    @staticmethod
    def generate_report(analysis_results: Dict[str, Any], output_path: Path) -> Path:
        """
        Write analysis results as Markdown.

        Args:
            analysis_results: Analysis summary returned by the pipeline
            output_path: Destination file

        Returns:
            Path to the written file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(MarkdownReporter.render(analysis_results))
        return output_path

    @staticmethod
    def render(analysis_results: Dict[str, Any]) -> str:
        """Render analysis results to a Markdown string."""
        sessions: List[Dict[str, Any]] = analysis_results.get("sessions") or []
        lines = [
            "# Threat Hunting Analysis Report",
            "",
            "## Summary",
            "",
            f"- Total events: {analysis_results.get('total_events', 0)}",
            f"- Correlated sessions: {analysis_results.get('total_sessions', 0)}",
            f"- Suspicious sessions: {analysis_results.get('suspicious_sessions', len(sessions))}",
            "",
        ]

        if not sessions:
            lines += ["No suspicious sessions were identified.", ""]
            return "\n".join(lines)

        for index, session in enumerate(sessions, 1):
            lines += MarkdownReporter._render_session(index, session)

        return "\n".join(lines)

    @staticmethod
    def _render_session(index: int, session: Dict[str, Any]) -> List[str]:
        info = session.get("session_info") or {}
        lines = [
            f"## Session {index}: {_code(info.get('session_id', 'unknown'))}",
            "",
            f"- Risk score: {float(info.get('risk_score') or 0):.2f}",
            f"- Events: {info.get('num_events', 0)}",
            f"- Start: {info.get('start_time') or 'N/A'}",
            f"- End: {info.get('end_time') or 'N/A'}",
        ]
        principals = info.get("principals") or []
        if principals:
            lines.append("- Principals: " + ", ".join(_code(p) for p in principals))
        source_ips = info.get("source_ips") or []
        if source_ips:
            lines.append("- Source IPs: " + ", ".join(_code(ip) for ip in source_ips))
        lines.append("")

        narrative = session.get("narrative") or {}
        summary = narrative.get("executive_summary")
        if summary:
            # The narrative agent's summary carries its own heading.
            lines += [str(summary).strip(), ""]

        kill_chain = session.get("kill_chain") or {}
        stages = kill_chain.get("active_stages") or []
        if stages:
            lines += ["### Kill Chain Stages", ""]
            lines += [f"- {stage}" for stage in stages]
            lines.append("")

        techniques = (session.get("mitre") or {}).get("techniques") or {}
        if techniques:
            lines += [
                "### MITRE ATT&CK Techniques",
                "",
                "| Technique | Name | Tactic | Events |",
                "|---|---|---|---|",
            ]
            for tech in techniques.values():
                lines.append(
                    f"| {tech.get('technique_id', '')} | {tech.get('technique_name', '')} "
                    f"| {tech.get('tactic', '')} | {tech.get('num_events', 0)} |"
                )
            lines.append("")

        iocs = (session.get("iocs") or {}).get("iocs") or {}
        if iocs:
            lines += ["### Indicators of Compromise", ""]
            for ioc_type, values in iocs.items():
                lines.append(f"- {ioc_type}: " + ", ".join(_code(v) for v in values))
            lines.append("")

        actions = (session.get("response_plan") or {}).get("immediate_actions") or []
        if actions:
            lines += ["### Immediate Actions", ""]
            for action in actions:
                if isinstance(action, dict):
                    lines.append(
                        f"- **{action.get('priority', '')}** {action.get('action', '')}"
                        f" ({action.get('timeframe', '')})"
                    )
                else:
                    lines.append(f"- {action}")
            lines.append("")

        return lines
