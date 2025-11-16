"""
Database migration utilities for AI Threat Hunting Simulator.

This module provides utilities for managing database schema migrations
using Alembic.
"""
import logging
from pathlib import Path
from typing import Optional

from alembic import command
from alembic.config import Config

logger = logging.getLogger(__name__)


class MigrationManager:
    """
    Manages database migrations using Alembic.

    This class provides a programmatic interface to Alembic migration
    commands for schema version control.
    """

    def __init__(self, alembic_ini_path: Optional[Path] = None):
        """
        Initialize migration manager.

        Args:
            alembic_ini_path: Path to alembic.ini configuration file
        """
        if alembic_ini_path is None:
            # Default to alembic.ini in the database directory
            alembic_ini_path = Path(__file__).parent / "alembic.ini"

        self.alembic_ini_path = alembic_ini_path
        self.alembic_cfg = None

        if alembic_ini_path.exists():
            self.alembic_cfg = Config(str(alembic_ini_path))

    def init(self, migrations_dir: Path) -> None:
        """
        Initialize Alembic migrations directory.

        Args:
            migrations_dir: Directory to store migrations
        """
        if self.alembic_cfg is None:
            self.alembic_cfg = Config()

        command.init(self.alembic_cfg, str(migrations_dir))
        logger.info(f"Initialized migrations directory: {migrations_dir}")

    def create_migration(
        self,
        message: str,
        autogenerate: bool = True
    ) -> None:
        """
        Create a new migration revision.

        Args:
            message: Migration message/description
            autogenerate: Auto-generate migration from model changes
        """
        if self.alembic_cfg is None:
            raise RuntimeError("Alembic not configured. Run init() first.")

        command.revision(
            self.alembic_cfg,
            message=message,
            autogenerate=autogenerate
        )
        logger.info(f"Created migration: {message}")

    def upgrade(self, revision: str = "head") -> None:
        """
        Upgrade database to a revision.

        Args:
            revision: Target revision (default: "head" for latest)
        """
        if self.alembic_cfg is None:
            raise RuntimeError("Alembic not configured.")

        command.upgrade(self.alembic_cfg, revision)
        logger.info(f"Upgraded database to: {revision}")

    def downgrade(self, revision: str = "-1") -> None:
        """
        Downgrade database to a revision.

        Args:
            revision: Target revision (default: "-1" for previous)
        """
        if self.alembic_cfg is None:
            raise RuntimeError("Alembic not configured.")

        command.downgrade(self.alembic_cfg, revision)
        logger.info(f"Downgraded database to: {revision}")

    def current(self) -> None:
        """Show current database revision."""
        if self.alembic_cfg is None:
            raise RuntimeError("Alembic not configured.")

        command.current(self.alembic_cfg)

    def history(self) -> None:
        """Show migration history."""
        if self.alembic_cfg is None:
            raise RuntimeError("Alembic not configured.")

        command.history(self.alembic_cfg)

    def stamp(self, revision: str) -> None:
        """
        Stamp database with a revision without running migrations.

        Args:
            revision: Revision to stamp
        """
        if self.alembic_cfg is None:
            raise RuntimeError("Alembic not configured.")

        command.stamp(self.alembic_cfg, revision)
        logger.info(f"Stamped database with revision: {revision}")


def create_initial_migration(
    database_url: str,
    migrations_dir: Path,
    message: str = "Initial database schema"
) -> None:
    """
    Create initial database migration.

    This is a convenience function for setting up migrations for the first time.

    Args:
        database_url: Database connection URL
        migrations_dir: Directory to store migrations
        message: Migration message

    Example:
        >>> from pathlib import Path
        >>> create_initial_migration(
        ...     database_url="sqlite:///threat_hunting.db",
        ...     migrations_dir=Path("./alembic"),
        ...     message="Initial schema"
        ... )
    """
    manager = MigrationManager()

    # Initialize if not already done
    if not migrations_dir.exists():
        manager.init(migrations_dir)

    # Create migration
    manager.create_migration(message, autogenerate=True)
    logger.info(f"Created initial migration: {message}")


# Example alembic.ini configuration template
ALEMBIC_INI_TEMPLATE = """
# Alembic configuration for AI Threat Hunting Simulator

[alembic]
# Path to migration scripts
script_location = alembic

# Template used to generate migration files
file_template = %%(year)d%%(month).2d%%(day).2d_%%(hour).2d%%(minute).2d_%%(rev)s_%%(slug)s

# Timezone for timestamps
timezone = UTC

# Truncate slug length for filenames
truncate_slug_length = 40

# Revision ID format
revision_environment = false

# SQLAlchemy URL - can be overridden via command line
sqlalchemy.url = sqlite:///threat_hunting.db

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""


def create_alembic_config(output_path: Path) -> None:
    """
    Create alembic.ini configuration file.

    Args:
        output_path: Path where alembic.ini should be created
    """
    output_path.write_text(ALEMBIC_INI_TEMPLATE.strip())
    logger.info(f"Created alembic.ini at: {output_path}")
