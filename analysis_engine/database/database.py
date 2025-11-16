"""
Database engine and session management for AI Threat Hunting Simulator.

This module provides database connection setup, session management, and
initialization utilities for the SQLAlchemy-based persistence layer.
"""
import logging
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator, Optional
from sqlalchemy import create_engine, event, pool
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

logger = logging.getLogger(__name__)


class DatabaseConfig:
    """Configuration for database connection."""

    def __init__(
        self,
        database_url: str,
        echo: bool = False,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_pre_ping: bool = True,
        pool_recycle: int = 3600,
    ):
        """
        Initialize database configuration.

        Args:
            database_url: Database connection URL (sync or async)
            echo: Enable SQL query logging
            pool_size: Number of connections to maintain in the pool
            max_overflow: Maximum overflow connections beyond pool_size
            pool_pre_ping: Enable connection health checks
            pool_recycle: Recycle connections after N seconds
        """
        self.database_url = database_url
        self.echo = echo
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_pre_ping = pool_pre_ping
        self.pool_recycle = pool_recycle

    @classmethod
    def from_url(cls, url: str, **kwargs) -> "DatabaseConfig":
        """Create configuration from database URL."""
        return cls(database_url=url, **kwargs)

    @classmethod
    def sqlite_memory(cls, **kwargs) -> "DatabaseConfig":
        """Create configuration for in-memory SQLite database."""
        return cls(database_url="sqlite:///:memory:", **kwargs)

    @classmethod
    def sqlite_file(cls, filepath: str, **kwargs) -> "DatabaseConfig":
        """Create configuration for file-based SQLite database."""
        return cls(database_url=f"sqlite:///{filepath}", **kwargs)

    @classmethod
    def postgresql(
        cls,
        host: str,
        database: str,
        user: str,
        password: str,
        port: int = 5432,
        **kwargs
    ) -> "DatabaseConfig":
        """Create configuration for PostgreSQL database."""
        url = f"postgresql://{user}:{password}@{host}:{port}/{database}"
        return cls(database_url=url, **kwargs)

    @classmethod
    def postgresql_async(
        cls,
        host: str,
        database: str,
        user: str,
        password: str,
        port: int = 5432,
        **kwargs
    ) -> "DatabaseConfig":
        """Create configuration for async PostgreSQL database."""
        url = f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{database}"
        return cls(database_url=url, **kwargs)


class DatabaseManager:
    """
    Manages database connections and sessions.

    Provides synchronous database operations with connection pooling
    and session management.
    """

    def __init__(self, config: DatabaseConfig):
        """
        Initialize database manager.

        Args:
            config: Database configuration
        """
        self.config = config
        self._engine: Optional[create_engine] = None
        self._session_factory: Optional[sessionmaker] = None

    @property
    def engine(self):
        """Get or create database engine."""
        if self._engine is None:
            self._engine = self._create_engine()
        return self._engine

    @property
    def session_factory(self) -> sessionmaker:
        """Get or create session factory."""
        if self._session_factory is None:
            self._session_factory = sessionmaker(
                bind=self.engine,
                class_=Session,
                expire_on_commit=False,
            )
        return self._session_factory

    def _create_engine(self):
        """Create SQLAlchemy engine with connection pooling."""
        # SQLite-specific configuration
        if self.config.database_url.startswith("sqlite"):
            engine = create_engine(
                self.config.database_url,
                echo=self.config.echo,
                connect_args={"check_same_thread": False},
                poolclass=pool.StaticPool,
            )
            # Enable foreign keys for SQLite
            @event.listens_for(engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        else:
            # PostgreSQL and other databases
            engine = create_engine(
                self.config.database_url,
                echo=self.config.echo,
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_pre_ping=self.config.pool_pre_ping,
                pool_recycle=self.config.pool_recycle,
            )

        logger.info(f"Database engine created: {self.config.database_url}")
        return engine

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Provide a transactional scope for database operations.

        Usage:
            with db_manager.session_scope() as session:
                session.add(obj)
                # Transaction automatically committed or rolled back

        Yields:
            Database session
        """
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Session rollback due to error: {e}")
            raise
        finally:
            session.close()

    def get_session(self) -> Session:
        """
        Get a new database session.

        Note: Caller is responsible for closing the session.

        Returns:
            Database session
        """
        return self.session_factory()

    def create_all(self) -> None:
        """Create all database tables."""
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created successfully")

    def drop_all(self) -> None:
        """Drop all database tables."""
        Base.metadata.drop_all(self.engine)
        logger.warning("All database tables dropped")

    def reset(self) -> None:
        """Drop and recreate all database tables."""
        self.drop_all()
        self.create_all()
        logger.info("Database reset complete")

    def dispose(self) -> None:
        """Dispose of the database engine and connection pool."""
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database engine disposed")


class AsyncDatabaseManager:
    """
    Manages async database connections and sessions.

    Provides asynchronous database operations with connection pooling
    for high-performance applications.
    """

    def __init__(self, config: DatabaseConfig):
        """
        Initialize async database manager.

        Args:
            config: Database configuration (must use async driver)
        """
        self.config = config
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker] = None

    @property
    def engine(self) -> AsyncEngine:
        """Get or create async database engine."""
        if self._engine is None:
            self._engine = self._create_engine()
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker:
        """Get or create async session factory."""
        if self._session_factory is None:
            self._session_factory = async_sessionmaker(
                bind=self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
        return self._session_factory

    def _create_engine(self) -> AsyncEngine:
        """Create async SQLAlchemy engine with connection pooling."""
        engine = create_async_engine(
            self.config.database_url,
            echo=self.config.echo,
            pool_size=self.config.pool_size,
            max_overflow=self.config.max_overflow,
            pool_pre_ping=self.config.pool_pre_ping,
            pool_recycle=self.config.pool_recycle,
        )

        logger.info(f"Async database engine created: {self.config.database_url}")
        return engine

    @asynccontextmanager
    async def session_scope(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Provide a transactional scope for async database operations.

        Usage:
            async with db_manager.session_scope() as session:
                session.add(obj)
                # Transaction automatically committed or rolled back

        Yields:
            Async database session
        """
        session = self.session_factory()
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Async session rollback due to error: {e}")
            raise
        finally:
            await session.close()

    def get_session(self) -> AsyncSession:
        """
        Get a new async database session.

        Note: Caller is responsible for closing the session.

        Returns:
            Async database session
        """
        return self.session_factory()

    async def create_all(self) -> None:
        """Create all database tables asynchronously."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully (async)")

    async def drop_all(self) -> None:
        """Drop all database tables asynchronously."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        logger.warning("All database tables dropped (async)")

    async def reset(self) -> None:
        """Drop and recreate all database tables asynchronously."""
        await self.drop_all()
        await self.create_all()
        logger.info("Database reset complete (async)")

    async def dispose(self) -> None:
        """Dispose of the async database engine and connection pool."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Async database engine disposed")


# Global database manager instances
_db_manager: Optional[DatabaseManager] = None
_async_db_manager: Optional[AsyncDatabaseManager] = None


def init_database(config: DatabaseConfig, create_tables: bool = True) -> DatabaseManager:
    """
    Initialize the global database manager.

    Args:
        config: Database configuration
        create_tables: Whether to create tables on initialization

    Returns:
        Initialized database manager
    """
    global _db_manager
    _db_manager = DatabaseManager(config)

    if create_tables:
        _db_manager.create_all()

    return _db_manager


async def init_async_database(
    config: DatabaseConfig,
    create_tables: bool = True
) -> AsyncDatabaseManager:
    """
    Initialize the global async database manager.

    Args:
        config: Database configuration (must use async driver)
        create_tables: Whether to create tables on initialization

    Returns:
        Initialized async database manager
    """
    global _async_db_manager
    _async_db_manager = AsyncDatabaseManager(config)

    if create_tables:
        await _async_db_manager.create_all()

    return _async_db_manager


def get_database() -> DatabaseManager:
    """
    Get the global database manager.

    Returns:
        Database manager

    Raises:
        RuntimeError: If database not initialized
    """
    if _db_manager is None:
        raise RuntimeError(
            "Database not initialized. Call init_database() first."
        )
    return _db_manager


def get_async_database() -> AsyncDatabaseManager:
    """
    Get the global async database manager.

    Returns:
        Async database manager

    Raises:
        RuntimeError: If async database not initialized
    """
    if _async_db_manager is None:
        raise RuntimeError(
            "Async database not initialized. Call init_async_database() first."
        )
    return _async_db_manager
