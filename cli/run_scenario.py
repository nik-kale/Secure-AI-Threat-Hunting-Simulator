#!/usr/bin/env python3
"""
CLI tool to run attack scenarios and generate analysis.
"""
import sys
import json
from pathlib import Path
from typing import Optional
import click
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.attack_traces.iam_priv_escalation.generator import (
    generate_iam_privilege_escalation_scenario
)
from generator.attack_traces.container_escape.generator import (
    generate_container_escape_scenario
)
from generator.attack_traces.cred_stuffing.generator import (
    generate_credential_stuffing_scenario
)
from generator.attack_traces.lateral_movement.generator import (
    generate_lateral_movement_scenario
)
from generator.attack_traces.data_exfiltration.generator import (
    generate_data_exfiltration_scenario
)
from generator.attack_traces.supply_chain.generator import (
    generate_supply_chain_scenario
)
from analysis_engine.pipeline import analyze_scenario

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


SCENARIOS = {
    "iam_priv_escalation": {
        "name": "IAM Privilege Escalation",
        "generator": generate_iam_privilege_escalation_scenario,
        "duration": 1.0,
    },
    "container_escape": {
        "name": "Container Breakout/Escape",
        "generator": generate_container_escape_scenario,
        "duration": 0.67,
    },
    "cred_stuffing": {
        "name": "Credential Stuffing",
        "generator": generate_credential_stuffing_scenario,
        "duration": 0.33,
    },
    "lateral_movement": {
        "name": "Lateral Movement (Multi-Account)",
        "generator": generate_lateral_movement_scenario,
        "duration": 1.5,
    },
    "data_exfiltration": {
        "name": "Data Exfiltration via S3",
        "generator": generate_data_exfiltration_scenario,
        "duration": 0.67,
    },
    "supply_chain": {
        "name": "Supply Chain Attack (CI/CD)",
        "generator": generate_supply_chain_scenario,
        "duration": 1.83,
    },
}


@click.command()
@click.option(
    '--scenario',
    type=click.Choice(list(SCENARIOS.keys())),
    required=True,
    help='Scenario to run'
)
@click.option(
    '--output',
    type=click.Path(),
    required=True,
    help='Output directory for telemetry and reports'
)
@click.option(
    '--account-id',
    default='123456789012',
    help='AWS account ID to use'
)
@click.option(
    '--region',
    default='us-east-1',
    help='AWS region to use'
)
@click.option(
    '--no-noise',
    is_flag=True,
    help='Disable benign background events'
)
@click.option(
    '--analyze/--no-analyze',
    default=True,
    help='Run analysis after generation'
)
def run_scenario(
    scenario: str,
    output: str,
    account_id: str,
    region: str,
    no_noise: bool,
    analyze: bool
) -> None:
    """
    Run an attack scenario and optionally analyze it.

    Examples:

        \b
        # Run IAM privilege escalation scenario
        python cli/run_scenario.py --scenario iam_priv_escalation --output ./output/iam_demo

        \b
        # Run container escape without analysis
        python cli/run_scenario.py --scenario container_escape --output ./output/container --no-analyze

        \b
        # Run with custom account ID
        python cli/run_scenario.py --scenario cred_stuffing --output ./output/cred --account-id 999888777666
    """
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    scenario_config = SCENARIOS[scenario]

    click.echo(f"\n{'='*60}")
    click.echo(f"Running Scenario: {scenario_config['name']}")
    click.echo(f"Output Directory: {output_path}")
    click.echo(f"{'='*60}\n")

    # Step 1: Generate telemetry
    click.echo("Step 1: Generating synthetic telemetry...")

    try:
        metadata = scenario_config["generator"](
            output_dir=output_path,
            account_id=account_id,
            region=region,
            duration_hours=scenario_config["duration"],
            add_noise=not no_noise
        )

        # Save metadata
        metadata_path = output_path / "metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        click.echo(f"✓ Generated {metadata['num_events']} events")
        click.echo(f"✓ Telemetry saved to: {output_path / 'telemetry.jsonl'}")
        click.echo(f"✓ Metadata saved to: {metadata_path}")

    except Exception as e:
        click.echo(f"✗ Error generating telemetry: {e}", err=True)
        sys.exit(1)

    # Step 2: Analyze (if enabled)
    if analyze:
        click.echo("\nStep 2: Analyzing telemetry...")

        try:
            telemetry_path = output_path / "telemetry.jsonl"

            results = analyze_scenario(
                telemetry_path=telemetry_path,
                output_dir=output_path,
                time_window=60,
                min_events=3
            )

            click.echo(f"✓ Analysis complete")
            click.echo(f"  - Total events analyzed: {results['total_events']}")
            click.echo(f"  - Sessions identified: {results['total_sessions']}")
            click.echo(f"  - Suspicious sessions: {results['suspicious_sessions']}")
            click.echo(f"\n✓ Reports saved to:")
            click.echo(f"  - JSON: {output_path / 'analysis_report.json'}")
            click.echo(f"  - Markdown: {output_path / 'analysis_report.md'}")
            click.echo(f"  - IOCs: {output_path / 'iocs.json'}")

        except Exception as e:
            click.echo(f"✗ Error during analysis: {e}", err=True)
            logger.exception(e)
            sys.exit(1)

    click.echo(f"\n{'='*60}")
    click.echo("✓ Scenario execution complete!")
    click.echo(f"{'='*60}\n")


@click.command()
def list_scenarios() -> None:
    """List available scenarios."""
    click.echo("\nAvailable Scenarios:\n")

    for key, config in SCENARIOS.items():
        click.echo(f"  {key}")
        click.echo(f"    Name: {config['name']}")
        click.echo(f"    Duration: {config['duration']} hours")
        click.echo()


def main():
    """Entry point for the CLI tool."""
    run_scenario()


if __name__ == '__main__':
    main()
