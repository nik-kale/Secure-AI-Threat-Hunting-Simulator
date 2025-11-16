#!/usr/bin/env python3
"""
CLI tool to validate telemetry traces against schema.
"""
import sys
import json
from pathlib import Path
import click
import jsonschema
import logging

sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.command()
@click.argument('telemetry_file', type=click.Path(exists=True))
@click.option(
    '--schema',
    type=click.Path(exists=True),
    default=None,
    help='Path to JSON schema file (default: auto-detect)'
)
@click.option(
    '--verbose',
    is_flag=True,
    help='Show detailed validation errors'
)
def validate_traces(
    telemetry_file: str,
    schema: str,
    verbose: bool
) -> None:
    """
    Validate telemetry traces against schema.

    Examples:

        \b
        # Validate a telemetry file
        python cli/validate_traces.py output/telemetry.jsonl

        \b
        # Validate with specific schema
        python cli/validate_traces.py output/telemetry.jsonl --schema generator/schemas/telemetry_event_schema.json
    """
    telemetry_path = Path(telemetry_file)

    # Load schema
    if schema is None:
        schema_path = Path("generator/schemas/telemetry_event_schema.json")
    else:
        schema_path = Path(schema)

    if not schema_path.exists():
        click.echo(f"✗ Schema file not found: {schema_path}", err=True)
        sys.exit(1)

    with open(schema_path) as f:
        schema_obj = json.load(f)

    click.echo(f"Validating: {telemetry_path}")
    click.echo(f"Schema: {schema_path}\n")

    # Load and validate events
    errors = []
    valid_count = 0
    total_count = 0

    try:
        with open(telemetry_path) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                total_count += 1

                try:
                    event = json.loads(line)
                    jsonschema.validate(instance=event, schema=schema_obj)
                    valid_count += 1

                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_num}: Invalid JSON - {e}")

                except jsonschema.ValidationError as e:
                    errors.append(f"Line {line_num}: Schema validation failed")
                    if verbose:
                        errors.append(f"  {e.message}")

    except Exception as e:
        click.echo(f"✗ Error reading file: {e}", err=True)
        sys.exit(1)

    # Report results
    click.echo(f"\nValidation Results:")
    click.echo(f"  Total events: {total_count}")
    click.echo(f"  Valid events: {valid_count}")
    click.echo(f"  Invalid events: {len(errors)}")

    if errors:
        click.echo(f"\n✗ Validation FAILED\n")

        if verbose or len(errors) <= 10:
            click.echo("Errors:")
            for error in errors[:50]:  # Limit to first 50
                click.echo(f"  {error}")
            if len(errors) > 50:
                click.echo(f"  ... and {len(errors) - 50} more errors")
        else:
            click.echo("Run with --verbose to see detailed errors")

        sys.exit(1)
    else:
        click.echo(f"\n✓ All events are valid!")
        sys.exit(0)


if __name__ == '__main__':
    validate_traces()
