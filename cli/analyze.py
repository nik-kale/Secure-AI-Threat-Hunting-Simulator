#!/usr/bin/env python3
"""
CLI tool to analyze telemetry files for threat hunting.
"""
import sys
import json
from pathlib import Path
from typing import Optional
import click
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis_engine.pipeline import ThreatHuntingPipeline

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
def cli():
    """AI Threat Hunting Simulator - Analysis Tool"""
    pass


@cli.command()
@click.argument(
    'telemetry_file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    '--output',
    '-o',
    type=click.Path(path_type=Path),
    help='Output directory for analysis reports (default: same as input file)'
)
@click.option(
    '--time-window',
    '-w',
    type=int,
    default=60,
    help='Time window for event correlation in minutes (default: 60)'
)
@click.option(
    '--min-events',
    '-m',
    type=int,
    default=3,
    help='Minimum events required to flag a session (default: 3)'
)
@click.option(
    '--risk-threshold',
    '-r',
    type=float,
    default=0.5,
    help='Risk score threshold for suspicious sessions (default: 0.5)'
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    help='Enable verbose output'
)
@click.option(
    '--format',
    '-f',
    type=click.Choice(['json', 'markdown', 'both']),
    default='both',
    help='Output format (default: both)'
)
def analyze(
    telemetry_file: Path,
    output: Optional[Path],
    time_window: int,
    min_events: int,
    risk_threshold: float,
    verbose: bool,
    format: str
) -> None:
    """
    Analyze telemetry file for threats and generate reports.

    Examples:

        \b
        # Analyze a telemetry file
        threat-analyze analyze ./output/telemetry.jsonl

        \b
        # Custom output directory
        threat-analyze analyze ./data/events.jsonl -o ./reports

        \b
        # Adjust correlation settings
        threat-analyze analyze ./data/events.jsonl -w 120 -m 5 -r 0.7

        \b
        # Verbose mode with JSON output only
        threat-analyze analyze ./data/events.jsonl -v -f json
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Determine output directory
    if output is None:
        output = telemetry_file.parent
    else:
        output.mkdir(parents=True, exist_ok=True)

    click.echo(f"\n{'='*70}")
    click.echo(f"AI Threat Hunting Simulator - Analysis")
    click.echo(f"{'='*70}\n")
    click.echo(f"Input file:       {telemetry_file}")
    click.echo(f"Output directory: {output}")
    click.echo(f"Time window:      {time_window} minutes")
    click.echo(f"Min events:       {min_events}")
    click.echo(f"Risk threshold:   {risk_threshold}")
    click.echo(f"\n{'='*70}\n")

    try:
        # Initialize pipeline
        click.echo("Initializing analysis pipeline...")
        pipeline = ThreatHuntingPipeline()

        # Run analysis
        click.echo(f"Analyzing telemetry from: {telemetry_file.name}")

        results = pipeline.analyze_telemetry_file(
            telemetry_file=telemetry_file,
            output_dir=output
        )

        # Display results
        click.echo(f"\n{'='*70}")
        click.echo("Analysis Results")
        click.echo(f"{'='*70}\n")

        click.echo(f"✓ Total events analyzed:     {results.get('total_events', 0)}")
        click.echo(f"✓ Sessions identified:       {results.get('total_sessions', 0)}")
        click.echo(f"✓ Suspicious sessions:       {results.get('suspicious_sessions', 0)}")

        if 'sessions' in results and results['sessions']:
            click.echo(f"\nTop Suspicious Sessions:")
            for i, session in enumerate(results['sessions'][:5], 1):
                click.echo(f"\n  {i}. Session ID: {session.get('session_id', 'N/A')}")
                click.echo(f"     Risk Score:  {session.get('risk_score', 0):.2f}")
                click.echo(f"     Event Count: {session.get('event_count', 0)}")
                click.echo(f"     Principal:   {session.get('principal', 'N/A')}")

                if 'mitre_techniques' in session:
                    techniques = session['mitre_techniques']
                    if techniques:
                        click.echo(f"     MITRE:       {', '.join(techniques[:3])}")

        # Report file paths
        click.echo(f"\n{'='*70}")
        click.echo("Generated Reports")
        click.echo(f"{'='*70}\n")

        if format in ['json', 'both']:
            json_report = output / "analysis_report.json"
            if json_report.exists():
                click.echo(f"✓ JSON report:     {json_report}")

            iocs_file = output / "iocs.json"
            if iocs_file.exists():
                click.echo(f"✓ IOCs:            {iocs_file}")

        if format in ['markdown', 'both']:
            md_report = output / "analysis_report.md"
            if md_report.exists():
                click.echo(f"✓ Markdown report: {md_report}")

        click.echo(f"\n{'='*70}")
        click.echo("✓ Analysis complete!")
        click.echo(f"{'='*70}\n")

    except FileNotFoundError as e:
        click.echo(f"✗ Error: File not found - {e}", err=True)
        sys.exit(1)
    except json.JSONDecodeError as e:
        click.echo(f"✗ Error: Invalid JSON in telemetry file - {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"✗ Error during analysis: {e}", err=True)
        if verbose:
            logger.exception(e)
        sys.exit(1)


@cli.command()
@click.argument(
    'telemetry_file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def stats(telemetry_file: Path) -> None:
    """
    Show statistics about a telemetry file without full analysis.

    Examples:

        \b
        # Show quick stats
        threat-analyze stats ./output/telemetry.jsonl
    """
    try:
        click.echo(f"\nAnalyzing: {telemetry_file}\n")

        # Count events and collect basic stats
        event_types = {}
        sources = {}
        principals = set()
        total_events = 0

        with open(telemetry_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    total_events += 1

                    # Count event types
                    event_type = event.get('event_type', 'unknown')
                    event_types[event_type] = event_types.get(event_type, 0) + 1

                    # Count sources
                    source = event.get('event_source', 'unknown')
                    sources[source] = sources.get(source, 0) + 1

                    # Collect principals
                    if 'principal' in event:
                        principals.add(event['principal'])

                except json.JSONDecodeError:
                    continue

        # Display stats
        click.echo(f"Total Events:        {total_events}")
        click.echo(f"Unique Principals:   {len(principals)}")
        click.echo(f"\nEvent Sources:")
        for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
            click.echo(f"  {source:20s} {count:6d} ({count/total_events*100:.1f}%)")

        click.echo(f"\nTop Event Types:")
        for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:10]:
            click.echo(f"  {event_type:30s} {count:6d} ({count/total_events*100:.1f}%)")

        click.echo()

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument(
    'telemetry_file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    '--limit',
    '-n',
    type=int,
    default=10,
    help='Number of events to display (default: 10)'
)
@click.option(
    '--filter-type',
    '-t',
    help='Filter by event type'
)
@click.option(
    '--filter-source',
    '-s',
    help='Filter by event source'
)
def show(
    telemetry_file: Path,
    limit: int,
    filter_type: Optional[str],
    filter_source: Optional[str]
) -> None:
    """
    Display events from a telemetry file.

    Examples:

        \b
        # Show first 10 events
        threat-analyze show ./output/telemetry.jsonl

        \b
        # Show 20 IAM events
        threat-analyze show ./data/events.jsonl -n 20 -s iam

        \b
        # Filter by event type
        threat-analyze show ./data/events.jsonl -t iam.create_role
    """
    try:
        count = 0
        click.echo(f"\nShowing events from: {telemetry_file}\n")

        with open(telemetry_file, 'r') as f:
            for line in f:
                if count >= limit:
                    break

                try:
                    event = json.loads(line.strip())

                    # Apply filters
                    if filter_type and event.get('event_type') != filter_type:
                        continue
                    if filter_source and event.get('event_source') != filter_source:
                        continue

                    count += 1
                    click.echo(f"Event #{count}")
                    click.echo(f"  Timestamp:    {event.get('timestamp')}")
                    click.echo(f"  Type:         {event.get('event_type')}")
                    click.echo(f"  Source:       {event.get('event_source')}")
                    click.echo(f"  Principal:    {event.get('principal', 'N/A')}")
                    click.echo(f"  Action:       {event.get('action', 'N/A')}")
                    click.echo(f"  Status:       {event.get('status', 'N/A')}")
                    click.echo(f"  Source IP:    {event.get('source_ip', 'N/A')}")
                    click.echo()

                except json.JSONDecodeError:
                    continue

        if count == 0:
            click.echo("No matching events found.")
        else:
            click.echo(f"Displayed {count} events")

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


def main():
    """Entry point for the CLI tool."""
    cli()


if __name__ == '__main__':
    main()
