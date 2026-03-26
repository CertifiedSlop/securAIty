"""
Storage Service

High-level service layer for storage operations.
"""

from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from securAIty.storage.database import DatabaseManager, DatabaseConfig
from securAIty.storage.repositories import (
    EventRepository,
    IncidentRepository,
    IncidentNoteRepository,
    AgentRepository,
    AgentTaskRepository,
    AuditRepository,
)


class StorageService:
    """
    High-level storage service.

    Provides convenient access to all repositories
    with session management.

    Attributes:
        db_manager: Database manager instance
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        """
        Initialize storage service.

        Args:
            db_manager: Optional database manager instance
        """
        self.db_manager = db_manager or DatabaseManager()

    def configure(
        self,
        url: str,
        pool_size: int = 10,
        max_overflow: int = 20,
        **kwargs,
    ) -> None:
        """
        Configure database connection.

        Args:
            url: Database connection URL
            pool_size: Connection pool size
            max_overflow: Maximum overflow connections
            **kwargs: Additional configuration options
        """
        self.db_manager.configure(
            url=url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            **kwargs,
        )

    async def initialize(self) -> None:
        """Initialize database connection."""
        await self.db_manager.initialize()

    async def close(self) -> None:
        """Close database connections."""
        await self.db_manager.close()

    async def create_tables(self) -> None:
        """Create all database tables."""
        await self.db_manager.create_tables()

    async def drop_tables(self) -> None:
        """Drop all database tables."""
        await self.db_manager.drop_tables()

    def get_repositories(self, session: AsyncSession) -> dict:
        """
        Get all repositories for a session.

        Args:
            session: Async database session

        Returns:
            Dictionary of repository instances
        """
        return {
            "events": EventRepository(session),
            "incidents": IncidentRepository(session),
            "incident_notes": IncidentNoteRepository(session),
            "agents": AgentRepository(session),
            "agent_tasks": AgentTaskRepository(session),
            "audit": AuditRepository(session),
        }

    async def get_event_repository(self, session: AsyncSession) -> EventRepository:
        """Get event repository."""
        return EventRepository(session)

    async def get_incident_repository(self, session: AsyncSession) -> IncidentRepository:
        """Get incident repository."""
        return IncidentRepository(session)

    async def get_agent_repository(self, session: AsyncSession) -> AgentRepository:
        """Get agent repository."""
        return AgentRepository(session)

    async def get_audit_repository(self, session: AsyncSession) -> AuditRepository:
        """Get audit repository."""
        return AuditRepository(session)

    @property
    def is_initialized(self) -> bool:
        """Check if database is initialized."""
        return self.db_manager._initialized

    async def health_check(self) -> bool:
        """Check database health."""
        return await self.db_manager.health_check()

    def get_pool_status(self) -> dict:
        """Get connection pool status."""
        return self.db_manager.get_pool_status()


_storage_service: Optional[StorageService] = None


def get_storage_service() -> StorageService:
    """
    Get or create global storage service.

    Returns:
        Storage service instance
    """
    global _storage_service
    if _storage_service is None:
        _storage_service = StorageService()
    return _storage_service
