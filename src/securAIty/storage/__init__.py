"""
securAIty Storage Layer

PostgreSQL storage layer with repository pattern for securAIty.

Provides:
- SQLAlchemy ORM models for all entities
- Repository pattern for data access
- Async database connection management
- Alembic migration support

Example usage:
    from securAIty.storage import (
        DatabaseManager,
        EventRepository,
        IncidentRepository,
        AgentRepository,
        AuditRepository,
    )
    
    db_manager = DatabaseManager()
    db_manager.configure(url="postgresql+asyncpg://...")
    await db_manager.initialize()
    
    async with db_manager.session() as session:
        event_repo = EventRepository(session)
        events = await event_repo.get_recent_events(minutes=60)
"""

from securAIty.storage.models import (
    Base,
    TimestampMixin,
    SecurityEvent,
    EventType,
    SeverityLevel,
    Incident,
    IncidentNote,
    IncidentStatus,
    IncidentSeverity,
    IncidentPriority,
    Agent,
    AgentTask,
    AgentType,
    AgentStatus,
    AuditLog,
    ActionType,
    AuditStatus,
)

from securAIty.storage.repositories import (
    BaseRepository,
    EventRepository,
    IncidentRepository,
    IncidentNoteRepository,
    AgentRepository,
    AgentTaskRepository,
    AuditRepository,
)

from securAIty.storage.database import (
    DatabaseManager,
    DatabaseConfig,
    get_database_manager,
    get_session,
    init_database,
    shutdown_database,
)

from securAIty.storage.migrations import (
    MigrationRunner,
    run_migrations,
    init_database as init_migrations,
)

from securAIty.storage.service import StorageService, get_storage_service

from securAIty.storage.schemas import (
    EventTypeEnum,
    SeverityLevelEnum,
    IncidentStatusEnum,
    IncidentSeverityEnum,
    IncidentPriorityEnum,
    AgentTypeEnum,
    AgentStatusEnum,
    ActionTypeEnum,
    AuditStatusEnum,
    SecurityEventBase,
    SecurityEventCreate,
    SecurityEventUpdate,
    SecurityEventResponse,
    IncidentBase,
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    IncidentNoteBase,
    IncidentNoteCreate,
    IncidentNoteResponse,
    AgentBase,
    AgentCreate,
    AgentUpdate,
    AgentResponse,
    AgentTaskBase,
    AgentTaskCreate,
    AgentTaskUpdate,
    AgentTaskResponse,
    AuditLogBase,
    AuditLogCreate,
    AuditLogResponse,
    PaginationParams,
    PaginatedResponse,
)

__all__ = [
    "Base",
    "TimestampMixin",
    "SecurityEvent",
    "EventType",
    "SeverityLevel",
    "Incident",
    "IncidentNote",
    "IncidentStatus",
    "IncidentSeverity",
    "IncidentPriority",
    "Agent",
    "AgentTask",
    "AgentType",
    "AgentStatus",
    "AuditLog",
    "ActionType",
    "AuditStatus",
    "BaseRepository",
    "EventRepository",
    "IncidentRepository",
    "IncidentNoteRepository",
    "AgentRepository",
    "AgentTaskRepository",
    "AuditRepository",
    "DatabaseManager",
    "DatabaseConfig",
    "get_database_manager",
    "get_session",
    "init_database",
    "shutdown_database",
    "MigrationRunner",
    "run_migrations",
    "init_migrations",
    "StorageService",
    "get_storage_service",
    "EventTypeEnum",
    "SeverityLevelEnum",
    "IncidentStatusEnum",
    "IncidentSeverityEnum",
    "IncidentPriorityEnum",
    "AgentTypeEnum",
    "AgentStatusEnum",
    "ActionTypeEnum",
    "AuditStatusEnum",
    "SecurityEventBase",
    "SecurityEventCreate",
    "SecurityEventUpdate",
    "SecurityEventResponse",
    "IncidentBase",
    "IncidentCreate",
    "IncidentUpdate",
    "IncidentResponse",
    "IncidentNoteBase",
    "IncidentNoteCreate",
    "IncidentNoteResponse",
    "AgentBase",
    "AgentCreate",
    "AgentUpdate",
    "AgentResponse",
    "AgentTaskBase",
    "AgentTaskCreate",
    "AgentTaskUpdate",
    "AgentTaskResponse",
    "AuditLogBase",
    "AuditLogCreate",
    "AuditLogResponse",
    "PaginationParams",
    "PaginatedResponse",
]
