"""
Database Connection Management

Async database connection management with connection pooling
and lifecycle management for securAIty.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from urllib.parse import urlparse

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import AsyncAdaptedQueuePool

from securAIty.storage.models.base import Base

logger = logging.getLogger(__name__)


class DatabaseConfig:
    """
    Database configuration container.

    Attributes:
        url: Database connection URL
        pool_size: Connection pool size
        max_overflow: Maximum overflow connections
        pool_timeout: Connection timeout
        pool_recycle: Connection recycle time
        echo: Enable SQL echo
        pool_pre_ping: Enable connection health checks
    """

    def __init__(
        self,
        url: str,
        pool_size: int = 10,
        max_overflow: int = 20,
        pool_timeout: int = 30,
        pool_recycle: int = 3600,
        echo: bool = False,
        pool_pre_ping: bool = True,
    ) -> None:
        """
        Initialize database configuration.

        Args:
            url: Database connection URL
            pool_size: Connection pool size
            max_overflow: Maximum overflow connections
            pool_timeout: Connection timeout in seconds
            pool_recycle: Connection recycle time in seconds
            echo: Enable SQL echo
            pool_pre_ping: Enable connection health checks
        """
        self.url = url
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
        self.echo = echo
        self.pool_pre_ping = pool_pre_ping


class DatabaseManager:
    """
    Database connection manager.

    Manages async database connections, sessions, and lifecycle.

    Attributes:
        config: Database configuration
        engine: Async SQLAlchemy engine
        session_factory: Async session factory
    """

    def __init__(self, config: Optional[DatabaseConfig] = None) -> None:
        """
        Initialize database manager.

        Args:
            config: Optional database configuration
        """
        self.config = config
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None
        self._initialized = False

    def configure(
        self,
        url: str,
        pool_size: int = 10,
        max_overflow: int = 20,
        pool_timeout: int = 30,
        pool_recycle: int = 3600,
        echo: bool = False,
        pool_pre_ping: bool = True,
    ) -> None:
        """
        Configure database connection.

        Args:
            url: Database connection URL
            pool_size: Connection pool size
            max_overflow: Maximum overflow connections
            pool_timeout: Connection timeout in seconds
            pool_recycle: Connection recycle time in seconds
            echo: Enable SQL echo
            pool_pre_ping: Enable connection health checks
        """
        self.config = DatabaseConfig(
            url=url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_recycle=pool_recycle,
            echo=echo,
            pool_pre_ping=pool_pre_ping,
        )

    def _create_engine(self) -> AsyncEngine:
        """
        Create async SQLAlchemy engine.

        Returns:
            Async engine instance
        """
        if not self.config:
            raise ValueError("Database not configured. Call configure() first.")

        connect_args = {}
        
        if self.config.url.startswith("postgresql+asyncpg"):
            connect_args = {
                "server_settings": {
                    "jit": "off",
                    "statement_timeout": "60000",
                },
            }

        engine = create_async_engine(
            self.config.url,
            echo=self.config.echo,
            poolclass=AsyncAdaptedQueuePool,
            pool_size=self.config.pool_size,
            max_overflow=self.config.max_overflow,
            pool_timeout=self.config.pool_timeout,
            pool_recycle=self.config.pool_recycle,
            pool_pre_ping=self.config.pool_pre_ping,
            connect_args=connect_args,
        )

        @event.listens_for(engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record) -> None:
            if "sqlite" in self.config.url:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        @event.listens_for(engine.sync_engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy) -> None:
            logger.debug("Connection checked out from pool")

        @event.listens_for(engine.sync_engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record) -> None:
            logger.debug("Connection returned to pool")

        return engine

    async def initialize(self) -> None:
        """
        Initialize database connection.

        Creates engine and session factory.
        """
        if self._initialized:
            return

        if not self.config:
            raise ValueError("Database not configured. Call configure() first.")

        self._engine = self._create_engine()
        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
        self._initialized = True

        logger.info(
                "Database initialized with pool_size=%d, max_overflow=%d",
                self.config.pool_size,
                self.config.max_overflow,
        )

    async def close(self) -> None:
        """
        Close database connections.

        Disposes of the engine and all pooled connections.
        """
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            self._initialized = False
            logger.info("Database connections closed")

    @property
    def engine(self) -> AsyncEngine:
        """
        Get async engine.

        Returns:
            Async engine instance
        """
        if not self._initialized:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """
        Get session factory.

        Returns:
            Async session factory
        """
        if not self._initialized:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._session_factory

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get async session context manager.

        Yields:
            Async session instance
        """
        if not self._session_factory:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        session = self._session_factory()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get transactional session context manager.

        Yields:
            Async session instance within transaction
        """
        if not self._session_factory:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        session = self._session_factory()
        try:
            async with session.begin():
                yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def create_tables(self) -> None:
        """
        Create all database tables.

        Creates tables for all registered models.
        """
        if not self._engine:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database tables created")

    async def drop_tables(self) -> None:
        """
        Drop all database tables.

        Drops all tables from the database.
        """
        if not self._engine:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

        logger.info("Database tables dropped")

    async def health_check(self) -> bool:
        """
        Check database connection health.

        Returns:
            True if healthy, False otherwise
        """
        if not self._engine:
            return False

        try:
            async with self._engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            logger.exception("Database health check failed")
            return False

    def get_pool_status(self) -> dict:
        """
        Get connection pool status.

        Returns:
            Dictionary with pool statistics
        """
        if not self._engine:
            return {"status": "not_initialized"}

        pool = self._engine.pool
        return {
            "status": "healthy",
            "pool_size": pool.size(),
            "checked_in": pool.checkedin(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
            "invalid": pool.invalidatedcount() if hasattr(pool, "invalidatedcount") else 0,
        }


from sqlalchemy import text


def get_database_manager() -> DatabaseManager:
    """
    Get or create global database manager.

    Returns:
        Database manager instance
    """
    global _database_manager
    if "_database_manager" not in globals():
        _database_manager = DatabaseManager()
    return _database_manager


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session from global manager.

    Yields:
        Async session instance
    """
    db_manager = get_database_manager()
    async with db_manager.session() as session:
        yield session


async def init_database(
    url: str,
    pool_size: int = 10,
    max_overflow: int = 20,
    **kwargs,
) -> DatabaseManager:
    """
    Initialize database with configuration.

    Args:
        url: Database connection URL
        pool_size: Connection pool size
        max_overflow: Maximum overflow connections
        **kwargs: Additional configuration options

    Returns:
        Initialized database manager
    """
    db_manager = get_database_manager()
    db_manager.configure(
        url=url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        **kwargs,
    )
    await db_manager.initialize()
    return db_manager


async def shutdown_database() -> None:
    """
    Shutdown database connections.

    Closes all connections and disposes of the engine.
    """
    if "_database_manager" in globals():
        await _database_manager.close()
