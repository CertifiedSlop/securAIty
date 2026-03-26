# ADR-004: Storage Pattern with Repository Abstraction

## Status

Accepted

## Date

2026-03-26

## Context

The securAIty platform requires persistent storage for:

1. **Security Events**: High-volume event data (10,000+ events/day)
2. **Incidents**: Security incident records with relationships
3. **Audit Logs**: Compliance-critical audit trail
4. **Agent State**: Agent metadata, task history, health status
5. **Configuration**: Security policies, agent configurations

### Storage Requirements

| Requirement | Description |
|-------------|-------------|
| **ACID Compliance** | Transactional integrity for security operations |
| **Query Flexibility** | Complex queries for incident investigation |
| **Scalability** | Handle growth from thousands to millions of records |
| **Retention** | Configurable retention policies (30 days to 7 years) |
| **Auditability** | Immutable audit log for compliance |
| **Performance** | Sub-100ms query response for operational data |

### Data Model Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Entity Relationship Diagram               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐         ┌──────────────┐                 │
│  │    Agent     │         │  Security    │                 │
│  │              │         │    Event     │                 │
│  │  id (PK)     │         │              │                 │
│  │  agent_type  │         │  id (PK)     │                 │
│  │  status      │         │  event_type  │                 │
│  │  metadata    │         │  severity    │                 │
│  └──────┬───────┘         │  payload     │                 │
│         │                 │  agent_id(FK)│                 │
│         │ 1:N             │  correlation │                 │
│         │                 └──────┬───────┘                 │
│         │                        │ 1:N                      │
│         │                        │                          │
│  ┌──────▼───────┐         ┌──────┴───────┐                 │
│  │     Task     │         │   Incident   │                 │
│  │              │         │              │                 │
│  │  id (PK)     │         │  id (PK)     │                 │
│  │  agent_id(FK)│         │  title       │                 │
│  │  status      │         │  severity    │                 │
│  │  result      │         │  status      │                 │
│  │  created_at  │         │  created_at  │                 │
│  └──────────────┘         └──────────────┘                 │
│                                                              │
│  ┌──────────────┐         ┌──────────────┐                 │
│  │  Audit Log   │         │  Repository  │                 │
│  │              │         │   (Base)     │                 │
│  │  id (PK)     │         │              │                 │
│  │  event_type  │         │  create()    │                 │
│  │  actor       │         │  read()      │                 │
│  │  action      │         │  update()    │                 │
│  │  timestamp   │         │  delete()    │                 │
│  │  metadata    │         │  query()     │                 │
│  └──────────────┘         └──────────────┘                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Decision

We implement a **Repository Pattern** with PostgreSQL as the primary datastore:

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Storage Architecture                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                 Application Layer                     │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │   │
│  │  │  Agent   │  │ Incident │  │  Audit   │           │   │
│  │  │ Service  │  │ Service  │  │ Service  │           │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘           │   │
│  └───────┼─────────────┼─────────────┼──────────────────┘   │
│          │             │             │                       │
│          ▼             ▼             ▼                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Repository Layer (Abstract)              │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │   │
│  │  │ AgentRepo    │  │ IncidentRepo │  │ AuditRepo  │  │   │
│  │  └──────────────┘  └──────────────┘  └────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│          │             │             │                       │
│          ▼             ▼             ▼                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              SQLAlchemy ORM Layer                     │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐     │   │
│  │  │ AgentModel │  │IncidentModel│ │AuditModel  │     │   │
│  │  └────────────┘  └────────────┘  └────────────┘     │   │
│  └──────────────────────────────────────────────────────┘   │
│          │             │             │                       │
│          ▼             ▼             ▼                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              PostgreSQL Database                      │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐     │   │
│  │  │   agents   │  │ incidents  │  │ audit_logs │     │   │
│  │  └────────────┘  └────────────┘  └────────────┘     │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Repository Interface

```python
from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Optional, List
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar('T')

class BaseRepository(ABC, Generic[T]):
    """Abstract base repository defining common CRUD operations."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    @abstractmethod
    async def create(self, entity: T) -> T:
        """Create a new entity."""
        pass
    
    @abstractmethod
    async def get_by_id(self, id: UUID) -> Optional[T]:
        """Retrieve entity by ID."""
        pass
    
    @abstractmethod
    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        **filters
    ) -> List[T]:
        """List entities with pagination and filters."""
        pass
    
    @abstractmethod
    async def update(self, id: UUID, updates: dict) -> Optional[T]:
        """Update an entity."""
        pass
    
    @abstractmethod
    async def delete(self, id: UUID) -> bool:
        """Delete an entity."""
        pass
```

### Concrete Repository Implementation

```python
from securAIty.storage.repositories.base import BaseRepository
from securAIty.storage.models.agent import AgentModel
from securAIty.agents.base import AgentMetadata

class AgentRepository(BaseRepository[AgentMetadata]):
    """Repository for agent metadata persistence."""
    
    async def create(self, agent: AgentMetadata) -> AgentMetadata:
        model = AgentModel.from_entity(agent)
        self.session.add(model)
        await self.session.commit()
        await self.session.refresh(model)
        return model.to_entity()
    
    async def get_by_id(self, agent_id: str) -> Optional[AgentMetadata]:
        model = await self.session.get(AgentModel, agent_id)
        return model.to_entity() if model else None
    
    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        agent_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[AgentMetadata]:
        query = select(AgentModel)
        
        if agent_type:
            query = query.where(AgentModel.agent_type == agent_type)
        if status:
            query = query.where(AgentModel.status == status)
        
        query = query.offset(skip).limit(limit)
        result = await self.session.execute(query)
        return [model.to_entity() for model in result.scalars()]
    
    async def update_status(
        self,
        agent_id: str,
        status: str,
    ) -> Optional[AgentMetadata]:
        model = await self.session.get(AgentModel, agent_id)
        if model:
            model.status = status
            model.updated_at = datetime.utcnow()
            await self.session.commit()
            await self.session.refresh(model)
            return model.to_entity()
        return None
```

### Database Configuration

```python
from securAIty.storage.database import DatabaseManager, DatabaseConfig

db_manager = DatabaseManager()

db_manager.configure(
    url="postgresql+asyncpg://user:password@localhost:5432/security_db",
    pool_size=10,          # Connections kept in pool
    max_overflow=20,       # Additional connections under load
    pool_timeout=30,       # Seconds to wait for connection
    pool_recycle=3600,     # Recycle connections after 1 hour
    pool_pre_ping=True,    # Verify connection before use
    echo=False,            # Disable SQL logging in production
)

await db_manager.initialize()
```

### Schema Design

#### Agents Table

```sql
CREATE TABLE agents (
    id VARCHAR(36) PRIMARY KEY,
    agent_type VARCHAR(50) NOT NULL,
    version VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'unknown',
    capabilities JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    
    INDEX idx_agents_type (agent_type),
    INDEX idx_agents_status (status),
    INDEX idx_agents_last_seen (last_seen_at)
);
```

#### Security Events Table

```sql
CREATE TABLE security_events (
    id VARCHAR(36) PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    correlation_id VARCHAR(36),
    incident_id VARCHAR(36),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    INDEX idx_events_type (event_type),
    INDEX idx_events_severity (severity),
    INDEX idx_events_correlation (correlation_id),
    INDEX idx_events_incident (incident_id),
    INDEX idx_events_created (created_at)
);

-- Partition by date for large-scale deployments
CREATE TABLE security_events_2026_03 PARTITION OF security_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
```

#### Audit Logs Table (Immutable)

```sql
CREATE TABLE audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    actor_id VARCHAR(36) NOT NULL,
    actor_type VARCHAR(20) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(36),
    outcome VARCHAR(20) NOT NULL,
    source_ip INET,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Prevent updates and deletes
    CONSTRAINT audit_logs_immutable CHECK (true)
);

-- Trigger to prevent updates
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_prevent_update
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
```

## Implementation

### Database Migrations

```python
# src/securAIty/storage/migrations/versions/001_initial.py

"""Initial database schema

Revision ID: 001
Revises: 
Create Date: 2026-03-26

"""
from alembic import op
import sqlalchemy as sa

def upgrade() -> None:
    op.create_table(
        'agents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('agent_type', sa.String(50), nullable=False),
        sa.Column('version', sa.String(20), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('capabilities', sa.JSON, nullable=False),
        sa.Column('metadata', sa.JSON, nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('last_seen_at', sa.TIMESTAMP(timezone=True)),
    )
    
    op.create_table(
        'security_events',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('source', sa.String(100), nullable=False),
        sa.Column('payload', sa.JSON, nullable=False),
        sa.Column('correlation_id', sa.String(36)),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True)),
    )
    
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('actor_id', sa.String(36), nullable=False),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('outcome', sa.String(20), nullable=False),
        sa.Column('metadata', sa.JSON, nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True)),
    )
```

### Session Management

```python
from securAIty.storage.database import get_session

async def create_agent(agent_data: dict):
    async with get_session() as session:
        repo = AgentRepository(session)
        agent = await repo.create(agent_data)
        return agent

# Transaction with explicit commit
async def update_incident_status(
    incident_id: str,
    new_status: str,
):
    async with get_session() as session:
        async with session.begin():
            repo = IncidentRepository(session)
            incident = await repo.update(incident_id, {"status": new_status})
            
            # Log audit entry in same transaction
            audit_repo = AuditRepository(session)
            await audit_repo.create({
                "event_type": "INCIDENT_UPDATE",
                "action": "update_status",
                "resource_id": incident_id,
                "outcome": "success",
            })
```

### Query Patterns

```python
# Complex query with joins and filters
async def get_incident_timeline(incident_id: str):
    async with get_session() as session:
        query = (
            select(SecurityEventModel)
            .where(SecurityEventModel.incident_id == incident_id)
            .order_by(SecurityEventModel.created_at.asc())
        )
        result = await session.execute(query)
        return result.scalars().all()

# Aggregation query
async def get_event_statistics(days: int = 7):
    async with get_session() as session:
        query = (
            select(
                SecurityEventModel.event_type,
                SecurityEventModel.severity,
                func.count().label('count'),
            )
            .where(
                SecurityEventModel.created_at >= 
                datetime.utcnow() - timedelta(days=days)
            )
            .group_by(
                SecurityEventModel.event_type,
                SecurityEventModel.severity,
            )
        )
        result = await session.execute(query)
        return result.all()
```

## Consequences

### Positive

1. **Separation of Concerns**: Business logic decoupled from data access
2. **Testability**: Repositories can be mocked for unit tests
3. **Flexibility**: Easy to swap database implementations
4. **Type Safety**: SQLAlchemy provides compile-time query validation
5. **Connection Management**: Pool handles connection lifecycle
6. **Migration Support**: Alembic manages schema evolution

### Negative

1. **Abstraction Overhead**: Additional layer between app and database
2. **Learning Curve**: Team must learn SQLAlchemy and Alembic
3. **N+1 Queries**: Requires careful query optimization
4. **Connection Pool Tuning**: Requires monitoring and adjustment

### Trade-offs

| Alternative | Why Not Selected |
|-------------|------------------|
| **Direct SQL** | No abstraction, harder to test, SQL injection risk |
| **DynamoDB** | Limited query flexibility, eventual consistency |
| **MongoDB** | No ACID transactions (pre-4.0), schema-less complexity |
| **SQLite** | Not suitable for concurrent access, limited scalability |
| **No Repository** | Tight coupling, harder to test and maintain |

## Performance Considerations

### Connection Pool Sizing

```python
# Calculate optimal pool size
# pool_size = ((core_count * 2) + effective_spindle_count)
# For 4-core CPU: pool_size = (4 * 2) + 1 = 9 ~ 10

# For high-concurrency workloads:
pool_size = 20
max_overflow = 40  # Allow burst to 60 connections
```

### Query Optimization

```python
# Use eager loading to avoid N+1
query = (
    select(IncidentModel)
    .options(
        selectinload(IncidentModel.events),
        selectinload(IncidentModel.assigned_to),
    )
)

# Use covering indexes
# CREATE INDEX idx_events_covering 
#   ON security_events (event_type, severity, created_at)
#   INCLUDE (payload);
```

### Retention Policies

```sql
-- Automatic cleanup of old events
CREATE OR REPLACE FUNCTION cleanup_old_events()
RETURNS void AS $$
BEGIN
    DELETE FROM security_events
    WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Schedule with pg_cron
SELECT cron.schedule(
    'cleanup-events',
    '0 2 * * *',  -- Daily at 2 AM
    $$SELECT cleanup_old_events()$$
);
```

## References

- [Repository Pattern](https://martinfowler.com/eaaCatalog/repository.html)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Alembic Migrations](https://alembic.sqlalchemy.org/)
- [PostgreSQL Performance](https://wiki.postgresql.org/wiki/Performance_Optimization)

## Related ADRs

- [ADR-001: Event-Driven Architecture](001-event-driven-architecture.md)
- [ADR-003: Security Model](003-security-model.md)
- [ADR-005: Python Async Design](005-python-async-design.md)
