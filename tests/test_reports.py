"""
Tests for analysis report writing (JSON, Markdown, IOC) and the pipeline that drives it.
"""

import json
from pathlib import Path

from analysis_engine.pipeline import ThreatHuntingPipeline
from analysis_engine.reports import HTMLReportGenerator, JsonReporter, MarkdownReporter
from generator.attack_traces.lateral_movement.generator import (
    generate_lateral_movement_scenario,
)


def _session(session_id, ips, principals):
    return {
        "session_info": {
            "session_id": session_id,
            "num_events": 3,
            "principals": principals,
            "source_ips": ips,
            "risk_score": 0.9,
        },
        "iocs": {"iocs": {"ip_addresses": ips, "principals": principals}},
    }


class TestJsonReporter:
    def test_merge_iocs_covers_every_session(self):
        sessions = [
            _session("s1", ["1.1.1.1"], ["arn:user/a"]),
            _session("s2", ["2.2.2.2", "1.1.1.1"], ["arn:user/b"]),
        ]

        merged = JsonReporter.merge_iocs(sessions)

        assert merged["ip_addresses"] == ["1.1.1.1", "2.2.2.2"]
        assert merged["principals"] == ["arn:user/a", "arn:user/b"]

    def test_ioc_report_counts_values(self, temp_output_dir):
        path = JsonReporter.generate_ioc_report(
            {"ip_addresses": ["1.1.1.1", "2.2.2.2"]}, temp_output_dir / "iocs.json"
        )

        report = json.loads(path.read_text())
        assert report["total_iocs"] == 2
        assert report["iocs"]["ip_addresses"] == ["1.1.1.1", "2.2.2.2"]


class TestMarkdownReporter:
    def test_lists_every_session(self):
        text = MarkdownReporter.render(
            {
                "total_events": 10,
                "total_sessions": 2,
                "suspicious_sessions": 2,
                "sessions": [
                    _session("s1", ["1.1.1.1"], ["arn:user/a"]),
                    _session("s2", ["2.2.2.2"], ["arn:user/b"]),
                ],
            }
        )

        assert "## Session 1: `s1`" in text
        assert "## Session 2: `s2`" in text

    def test_telemetry_values_cannot_break_out_of_code_spans(self):
        text = MarkdownReporter.render(
            {
                "sessions": [_session("s1", ["1.1.1.1"], ["evil`\n# injected"])],
            }
        )

        assert "# injected" not in text.splitlines()
        assert "`evil' # injected`" in text

    def test_reports_absence_of_suspicious_sessions(self):
        text = MarkdownReporter.render({"total_events": 5, "sessions": []})

        assert "No suspicious sessions were identified." in text


class TestPipelineReports:
    def test_reports_cover_all_suspicious_sessions(self, tmp_path):
        """Lateral movement yields several suspicious sessions; every one must be reported."""
        generate_lateral_movement_scenario(output_dir=tmp_path, add_noise=False)
        telemetry = tmp_path / "telemetry.jsonl"

        out = tmp_path / "out"
        summary = ThreatHuntingPipeline(enable_database=False).analyze_telemetry_file(
            telemetry, out
        )

        assert summary["suspicious_sessions"] >= 2
        report = json.loads((out / "analysis_report.json").read_text())
        assert report["suspicious_sessions"] == summary["suspicious_sessions"]
        assert len(report["sessions"]) == summary["suspicious_sessions"]

        reported_ips = set(
            json.loads((out / "iocs.json").read_text())["iocs"]["ip_addresses"]
        )
        for session in summary["sessions"]:
            assert set(session["iocs"]["iocs"].get("ip_addresses", [])) <= reported_ips

        markdown = (out / "analysis_report.md").read_text()
        for index in range(1, summary["suspicious_sessions"] + 1):
            assert f"## Session {index}:" in markdown

    def test_reports_written_without_suspicious_sessions(self, tmp_path):
        telemetry = tmp_path / "telemetry.jsonl"
        telemetry.write_text("")
        out = tmp_path / "out"

        ThreatHuntingPipeline(enable_database=False).analyze_telemetry_file(
            telemetry, out
        )

        assert json.loads((out / "analysis_report.json").read_text())["sessions"] == []
        assert (out / "analysis_report.md").exists()
        assert (out / "iocs.json").exists()


class TestHTMLReportGenerator:
    def test_telemetry_values_are_escaped(self, temp_output_dir):
        payload = "<script>alert(1)</script>"
        result = {
            "total_events": 1,
            "suspicious_sessions": 1,
            "sessions": [{"session_info": {"principals": [payload]}}],
        }

        path = HTMLReportGenerator().generate(result, temp_output_dir / "report.html")

        page = path.read_text()
        assert payload not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page

    def test_sessions_detected_shows_a_count(self, temp_output_dir):
        result = {"suspicious_sessions": 2, "sessions": [{}, {}]}

        page = (
            HTMLReportGenerator()
            .generate(result, temp_output_dir / "r.html")
            .read_text()
        )

        assert "<td>Sessions Detected</td><td>2</td>" in page
