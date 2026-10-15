"""
Tests for the command-line entry points, run the way CI runs them.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from cli.analyze import cli
from generator.attack_traces.lateral_movement.generator import (
    generate_lateral_movement_scenario,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestAnalyzeCommand:
    def test_analyze_writes_reports_and_lists_sessions(self, tmp_path):
        generate_lateral_movement_scenario(output_dir=tmp_path, add_noise=True)
        out = tmp_path / "analysis"

        result = CliRunner().invoke(
            cli, ["analyze", str(tmp_path / "telemetry.jsonl"), "-o", str(out)]
        )

        assert result.exit_code == 0, result.output
        assert (out / "analysis_report.json").exists()
        assert (out / "analysis_report.md").exists()
        assert (out / "iocs.json").exists()
        # Session details come from each session's session_info, not "N/A".
        assert (
            "Session ID: sess-" in result.output
            or "Session ID: principal-" in result.output
        )
        assert "Session ID: N/A" not in result.output


@pytest.mark.parametrize("scenario", ["iam_priv_escalation", "cred_stuffing"])
def test_scenario_module_writes_to_output_dir_in_cwd(tmp_path, scenario):
    """`python -m generator.attack_traces.<name>.generator` writes ./output/<name>/telemetry.jsonl."""
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))

    subprocess.run(
        [sys.executable, "-m", f"generator.attack_traces.{scenario}.generator"],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
    )

    assert (tmp_path / "output" / scenario / "telemetry.jsonl").exists()
