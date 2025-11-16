"""
Command-line interface for database management.

This module provides CLI commands for managing the threat hunting database,
including initialization, migrations, and data inspection.

Usage:
    python -m analysis_engine.database.cli init --url sqlite:///threat_hunting.db
    python -m analysis_engine.database.cli reset --url sqlite:///threat_hunting.db
    python -m analysis_engine.database.cli stats --url sqlite:///threat_hunting.db
"""
import click
import logging
from pathlib import Path
from typing import Optional

from .database import DatabaseConfig, DatabaseManager
from .repository import (
    AnalysisRepository,
    SessionRepository,
    IOCRepository,
    ThreatIntelligenceRepository,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
def cli():
    """AI Threat Hunting Simulator - Database Management CLI."""
    pass


@cli.command()
@click.option(
    '--url',
    required=True,
    help='Database connection URL (e.g., sqlite:///threat_hunting.db)'
)
@click.option(
    '--echo/--no-echo',
    default=False,
    help='Enable SQL query logging'
)
def init(url: str, echo: bool):
    """Initialize database and create all tables."""
    click.echo(f"Initializing database: {url}")

    config = DatabaseConfig.from_url(url, echo=echo)
    db = DatabaseManager(config)

    try:
        db.create_all()
        click.echo(click.style("✓ Database initialized successfully!", fg='green'))
    except Exception as e:
        click.echo(click.style(f"✗ Error: {e}", fg='red'))
        raise


@cli.command()
@click.option(
    '--url',
    required=True,
    help='Database connection URL'
)
@click.confirmation_option(
    prompt='Are you sure you want to drop all tables and recreate them?'
)
def reset(url: str):
    """Drop all tables and recreate them (DESTRUCTIVE)."""
    click.echo(f"Resetting database: {url}")

    config = DatabaseConfig.from_url(url)
    db = DatabaseManager(config)

    try:
        db.reset()
        click.echo(click.style("✓ Database reset complete!", fg='green'))
    except Exception as e:
        click.echo(click.style(f"✗ Error: {e}", fg='red'))
        raise


@cli.command()
@click.option(
    '--url',
    required=True,
    help='Database connection URL'
)
def stats(url: str):
    """Show database statistics."""
    config = DatabaseConfig.from_url(url)
    db = DatabaseManager(config)

    try:
        with db.session_scope() as session:
            analysis_repo = AnalysisRepository(session)
            session_repo = SessionRepository(session)
            ioc_repo = IOCRepository(session)

            # Get counts
            all_runs = analysis_repo.list_analysis_runs(limit=1000)
            total_runs = len(all_runs)

            total_sessions = 0
            total_iocs = 0
            malicious_sessions = 0

            for run in all_runs:
                sessions = session_repo.get_sessions_by_analysis_run(run.id)
                total_sessions += len(sessions)
                malicious_sessions += sum(1 for s in sessions if s.is_malicious)

                for s in sessions:
                    iocs = ioc_repo.get_iocs_by_session(s.id)
                    total_iocs += len(iocs)

            # Display statistics
            click.echo("\n" + "=" * 60)
            click.echo(click.style("Database Statistics", fg='cyan', bold=True))
            click.echo("=" * 60)
            click.echo(f"Total Analysis Runs:      {total_runs}")
            click.echo(f"Total Detected Sessions:  {total_sessions}")
            click.echo(f"Malicious Sessions:       {malicious_sessions}")
            click.echo(f"Total IOCs:               {total_iocs}")
            click.echo("=" * 60 + "\n")

            # Show recent runs
            if all_runs:
                click.echo(click.style("Recent Analysis Runs:", fg='cyan', bold=True))
                for run in all_runs[:5]:
                    click.echo(
                        f"  [{run.id}] {run.scenario_name} - "
                        f"{run.num_events} events, {run.num_sessions} sessions "
                        f"({run.created_at.strftime('%Y-%m-%d %H:%M:%S')})"
                    )
                click.echo()

    except Exception as e:
        click.echo(click.style(f"✗ Error: {e}", fg='red'))
        raise


@cli.command()
@click.option(
    '--url',
    required=True,
    help='Database connection URL'
)
@click.option(
    '--run-id',
    type=int,
    help='Analysis run ID to inspect'
)
@click.option(
    '--scenario',
    help='Scenario name to filter by'
)
@click.option(
    '--limit',
    type=int,
    default=10,
    help='Maximum number of runs to show'
)
def list_runs(url: str, run_id: Optional[int], scenario: Optional[str], limit: int):
    """List analysis runs."""
    config = DatabaseConfig.from_url(url)
    db = DatabaseManager(config)

    with db.session_scope() as session:
        analysis_repo = AnalysisRepository(session)

        if run_id:
            # Show specific run
            run = analysis_repo.get_analysis_run(run_id, include_sessions=True)
            if not run:
                click.echo(click.style(f"Run {run_id} not found", fg='red'))
                return

            click.echo("\n" + "=" * 60)
            click.echo(click.style(f"Analysis Run #{run.id}", fg='cyan', bold=True))
            click.echo("=" * 60)
            click.echo(f"Scenario:          {run.scenario_name}")
            click.echo(f"Created:           {run.created_at}")
            click.echo(f"Total Events:      {run.num_events}")
            click.echo(f"Total Sessions:    {run.num_sessions}")
            click.echo(f"Suspicious:        {run.num_suspicious_sessions}")
            click.echo(f"Time Window:       {run.time_window_minutes} minutes")
            click.echo(f"Risk Threshold:    {run.risk_threshold}")
            if run.telemetry_file_path:
                click.echo(f"Telemetry File:    {run.telemetry_file_path}")
            if run.analysis_duration_seconds:
                click.echo(f"Duration:          {run.analysis_duration_seconds:.2f}s")
            click.echo("=" * 60 + "\n")

            # Show sessions
            if run.detected_sessions:
                click.echo(click.style("Detected Sessions:", fg='cyan', bold=True))
                for sess in run.detected_sessions:
                    status = click.style("MALICIOUS", fg='red') if sess.is_malicious else click.style("Clean", fg='green')
                    click.echo(
                        f"  [{sess.id}] {sess.session_id} - "
                        f"Risk: {sess.risk_score:.2f} - {status}"
                    )
                click.echo()
        else:
            # List runs
            runs = analysis_repo.list_analysis_runs(
                scenario_name=scenario,
                limit=limit,
                order_by_recent=True
            )

            if not runs:
                click.echo("No analysis runs found")
                return

            click.echo("\n" + "=" * 80)
            click.echo(click.style("Analysis Runs", fg='cyan', bold=True))
            click.echo("=" * 80)
            click.echo(f"{'ID':<6} {'Scenario':<30} {'Events':<8} {'Sessions':<10} {'Created':<20}")
            click.echo("-" * 80)

            for run in runs:
                click.echo(
                    f"{run.id:<6} {run.scenario_name:<30} "
                    f"{run.num_events:<8} {run.num_sessions:<10} "
                    f"{run.created_at.strftime('%Y-%m-%d %H:%M:%S'):<20}"
                )
            click.echo("=" * 80 + "\n")


@cli.command()
@click.option(
    '--url',
    required=True,
    help='Database connection URL'
)
@click.option(
    '--min-risk',
    type=float,
    default=0.0,
    help='Minimum risk score'
)
@click.option(
    '--malicious-only',
    is_flag=True,
    help='Show only malicious sessions'
)
@click.option(
    '--limit',
    type=int,
    default=20,
    help='Maximum number of sessions to show'
)
def list_sessions(url: str, min_risk: float, malicious_only: bool, limit: int):
    """List detected sessions."""
    config = DatabaseConfig.from_url(url)
    db = DatabaseManager(config)

    with db.session_scope() as session:
        session_repo = SessionRepository(session)

        sessions = session_repo.get_sessions_by_risk(
            min_risk_score=min_risk,
            malicious_only=malicious_only,
            limit=limit,
        )

        if not sessions:
            click.echo("No sessions found matching criteria")
            return

        click.echo("\n" + "=" * 100)
        click.echo(click.style("Detected Sessions", fg='cyan', bold=True))
        click.echo("=" * 100)
        click.echo(
            f"{'ID':<6} {'Session ID':<35} {'Risk':<6} {'Malicious':<11} "
            f"{'Events':<8} {'MITRE Techniques':<20}"
        )
        click.echo("-" * 100)

        for sess in sessions:
            status = click.style("YES", fg='red') if sess.is_malicious else click.style("NO", fg='green')
            techniques = ', '.join(sess.mitre_techniques[:3]) if sess.mitre_techniques else '-'
            if len(sess.mitre_techniques) > 3:
                techniques += '...'

            click.echo(
                f"{sess.id:<6} {sess.session_id:<35} "
                f"{sess.risk_score:<6.2f} {status:<11} "
                f"{sess.num_events:<8} {techniques:<20}"
            )

        click.echo("=" * 100 + "\n")


@cli.command()
@click.option(
    '--url',
    required=True,
    help='Database connection URL'
)
@click.option(
    '--type',
    'ioc_type',
    help='Filter by IOC type (ip, domain, url, hash, etc.)'
)
@click.option(
    '--severity',
    help='Filter by severity (low, medium, high, critical)'
)
@click.option(
    '--limit',
    type=int,
    default=50,
    help='Maximum number of IOCs to show'
)
def list_iocs(url: str, ioc_type: Optional[str], severity: Optional[str], limit: int):
    """List extracted IOCs."""
    config = DatabaseConfig.from_url(url)
    db = DatabaseManager(config)

    with db.session_scope() as session:
        ioc_repo = IOCRepository(session)

        if ioc_type:
            iocs = ioc_repo.get_iocs_by_type(ioc_type, limit=limit)
        elif severity:
            iocs = ioc_repo.get_iocs_by_severity(severity, limit=limit)
        else:
            # Get all IOCs (this is inefficient for large datasets)
            from sqlalchemy import select
            from .models import IOC
            query = select(IOC).limit(limit)
            result = session.execute(query)
            iocs = list(result.scalars().all())

        if not iocs:
            click.echo("No IOCs found matching criteria")
            return

        click.echo("\n" + "=" * 90)
        click.echo(click.style("Indicators of Compromise", fg='cyan', bold=True))
        click.echo("=" * 90)
        click.echo(
            f"{'ID':<6} {'Type':<10} {'Value':<40} {'Severity':<10} {'Enriched':<10}"
        )
        click.echo("-" * 90)

        for ioc in iocs:
            enriched = click.style("YES", fg='green') if ioc.enriched else click.style("NO", fg='yellow')
            value = ioc.value[:40] if len(ioc.value) > 40 else ioc.value

            click.echo(
                f"{ioc.id:<6} {ioc.ioc_type:<10} {value:<40} "
                f"{ioc.severity:<10} {enriched:<10}"
            )

        click.echo("=" * 90 + "\n")


@cli.command()
@click.option(
    '--url',
    required=True,
    help='Database connection URL'
)
@click.option(
    '--run-id',
    type=int,
    required=True,
    help='Analysis run ID to delete'
)
@click.confirmation_option(
    prompt='Are you sure you want to delete this analysis run?'
)
def delete_run(url: str, run_id: int):
    """Delete an analysis run and all associated data."""
    config = DatabaseConfig.from_url(url)
    db = DatabaseManager(config)

    with db.session_scope() as session:
        analysis_repo = AnalysisRepository(session)

        if analysis_repo.delete_analysis_run(run_id):
            click.echo(click.style(f"✓ Deleted analysis run {run_id}", fg='green'))
        else:
            click.echo(click.style(f"✗ Analysis run {run_id} not found", fg='red'))


if __name__ == '__main__':
    cli()
