"""
Migration Script Runner

Async migration runner for securAIty database migrations.
"""

import asyncio
from pathlib import Path
from typing import Optional

from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine

from securAIty.storage.models.base import Base
from securAIty.storage.models import (
    SecurityEvent,
    Incident,
    IncidentNote,
    Agent,
    AgentTask,
    AuditLog,
)


class MigrationRunner:
    """
    Database migration runner.

    Provides programmatic migration execution for securAIty.

    Attributes:
        config_path: Path to Alembic configuration
        database_url: Database connection URL
    """

    def __init__(
        self,
        database_url: str,
        config_path: Optional[str] = None,
    ) -> None:
        """
        Initialize migration runner.

        Args:
            database_url: Database connection URL
            config_path: Optional path to Alembic config
        """
        self.database_url = database_url
        self.config_path = config_path or str(
            Path(__file__).parent / "alembic.ini"
        )
        self._engine: Optional[AsyncEngine] = None

    def _get_alembic_config(self) -> Config:
        """
        Get Alembic configuration.

        Returns:
            Alembic config instance
        """
        alembic_cfg = Config(self.config_path)
        alembic_cfg.set_main_option("sqlalchemy.url", self.database_url)
        return alembic_cfg

    async def upgrade(self, revision: str = "head") -> None:
        """
        Upgrade database to revision.

        Args:
            revision: Target revision (default: head)
        """
        alembic_cfg = self._get_alembic_config()
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: command.upgrade(alembic_cfg, revision),
        )

    async def downgrade(self, revision: str = "-1") -> None:
        """
        Downgrade database to revision.

        Args:
            revision: Target revision (default: previous)
        """
        alembic_cfg = self._get_alembic_config()
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: command.downgrade(alembic_cfg, revision),
        )

    async def current(self) -> Optional[str]:
        """
        Get current revision.

        Returns:
            Current revision string or None
        """
        alembic_cfg = self._get_alembic_config()
        
        from alembic.script import ScriptDirectory
        from alembic.runtime.migration import MigrationContext
        from sqlalchemy import create_engine
        
        sync_url = self.database_url.replace("postgresql+asyncpg://", "postgresql://")
        engine = create_engine(sync_url)
        
        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            current = context.get_current_revision()
            return current

    async def history(self) -> list:
        """
        Get migration history.

        Returns:
            List of migration history entries
        """
        alembic_cfg = self._get_alembic_config()
        
        from alembic.script import ScriptDirectory
        
        script = ScriptDirectory.from_config(alembic_cfg)
        history = []
        
        for revision in script.walk_revisions():
            history.append({
                "revision": revision.revision,
                "down_revision": revision.down_revision,
                "message": revision.doc,
            })
        
        return history

    async def stamp(self, revision: str = "head") -> None:
        """
        Stamp database with revision.

        Args:
            revision: Revision to stamp
        """
        alembic_cfg = self._get_alembic_config()
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: command.stamp(alembic_cfg, revision),
        )

    async def create_migration(self, message: str) -> str:
        """
        Create new migration file.

        Args:
            message: Migration message

        Returns:
            Path to created migration file
        """
        alembic_cfg = self._get_alembic_config()
        
        import tempfile
        from alembic.util import CommandError
        
        try:
            command.revision(alembic_cfg, message=message, autogenerate=True)
            
            script = ScriptDirectory.from_config(alembic_cfg)
            head = script.get_current_head()
            
            migrations_dir = Path(self.config_path).parent / "versions"
            
            if head:
                files = sorted(migrations_dir.glob(f"{head}_*.py"))
                if files:
                    return str(files[-1])
            
            return str(migrations_dir)
        except CommandError as e:
            raise RuntimeError(f"Failed to create migration: {e}")

    async def check(self) -> bool:
        """
        Check if database is up to date.

        Returns:
            True if up to date, False otherwise
        """
        current = await self.current()
        alembic_cfg = self._get_alembic_config()
        
        from alembic.script import ScriptDirectory
        
        script = ScriptDirectory.from_config(alembic_cfg)
        head = script.get_current_head()
        
        return current == head

    async def create_tables(self) -> None:
        """
        Create all tables directly (without migrations).

        Useful for testing or initial setup.
        """
        from sqlalchemy.ext.asyncio import create_async_engine
        
        self._engine = create_async_engine(
            self.database_url,
            echo=False,
        )

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        await self._engine.dispose()

    async def drop_tables(self) -> None:
        """
        Drop all tables directly.

        Useful for testing or cleanup.
        """
        from sqlalchemy.ext.asyncio import create_async_engine
        
        self._engine = create_async_engine(
            self.database_url,
            echo=False,
        )

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

        await self._engine.dispose()

    async def close(self) -> None:
        """Close database connections."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None


async def run_migrations(
    database_url: str,
    revision: str = "head",
) -> None:
    """
    Run database migrations.

    Args:
        database_url: Database connection URL
        revision: Target revision
    """
    runner = MigrationRunner(database_url)
    try:
        await runner.upgrade(revision)
    finally:
        await runner.close()


async def init_database(
    database_url: str,
) -> None:
    """
    Initialize database with all tables.

    Args:
        database_url: Database connection URL
    """
    runner = MigrationRunner(database_url)
    try:
        await runner.create_tables()
    finally:
        await runner.close()
