"""
Agent Model

Model for tracking security agents and their state.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from sqlalchemy import BigInteger, DateTime, Enum as SQLEnum, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from securAIty.storage.models.base import Base, TimestampMixin


class AgentType(str, Enum):
    """Agent types."""

    DETECTOR = "detector"
    ANALYZER = "analyzer"
    RESPONDER = "responder"
    COLLECTOR = "collector"
    ENRICHER = "enricher"
    CUSTOM = "custom"


class AgentStatus(str, Enum):
    """Agent operational status."""

    IDLE = "idle"
    RUNNING = "running"
    BUSY = "busy"
    PAUSED = "paused"
    ERROR = "error"
    STOPPED = "stopped"
    UNREACHABLE = "unreachable"


class Agent(Base, TimestampMixin):
    """
    Security agent entity.

    Tracks agent registration, status, and capabilities.

    Attributes:
        agent_id: Primary key
        agent_type: Type of agent
        status: Current operational status
        metadata: Agent metadata and capabilities
        last_heartbeat: Last heartbeat timestamp
        config: Agent configuration
    """

    __tablename__ = "agents"

    agent_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )
    agent_type: Mapped[str] = mapped_column(
        SQLEnum(AgentType, name="agent_type_enum"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        SQLEnum(AgentStatus, name="agent_status_enum"),
        nullable=False,
        default=AgentStatus.IDLE,
        index=True,
    )
    version: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    metadata: Mapped[dict[str, Any]] = mapped_column(
        default=dict,
    )
    capabilities: Mapped[list[str]] = mapped_column(
        default=list,
    )
    config: Mapped[dict[str, Any]] = mapped_column(
        default=dict,
    )
    last_heartbeat: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_error: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    last_error_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    tasks_completed: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
    )
    tasks_failed: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
    )
    host: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    port: Mapped[Optional[int]] = mapped_column(
        nullable=True,
    )
    endpoint: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "idx_agents_type_status",
            "agent_type",
            "status",
        ),
        Index(
            "idx_agents_heartbeat",
            "last_heartbeat",
        ),
    )

    def __repr__(self) -> str:
        return f"Agent(agent_id={self.agent_id}, name={self.name}, type={self.agent_type}, status={self.status})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "agent_type": self.agent_type.value if isinstance(self.agent_type, AgentType) else self.agent_type,
            "status": self.status.value if isinstance(self.status, AgentStatus) else self.status,
            "version": self.version,
            "description": self.description,
            "metadata": self.metadata,
            "capabilities": self.capabilities,
            "config": self.config,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "registered_at": self.registered_at.isoformat(),
            "last_error": self.last_error,
            "last_error_at": self.last_error_at.isoformat() if self.last_error_at else None,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "host": self.host,
            "port": self.port,
            "endpoint": self.endpoint,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def is_healthy(self, heartbeat_threshold_seconds: int = 60) -> bool:
        if self.status in [AgentStatus.ERROR, AgentStatus.STOPPED, AgentStatus.UNREACHABLE]:
            return False
        if self.last_heartbeat is None:
            return False
        elapsed = (datetime.now(timezone.utc) - self.last_heartbeat).total_seconds()
        return elapsed < heartbeat_threshold_seconds


class AgentTask(Base, TimestampMixin):
    """
    Agent task tracking.

    Attributes:
        task_id: Primary key
        agent_id: Foreign key to agent
        task_type: Type of task
        status: Task status
        payload: Task data
        result: Task result
    """

    __tablename__ = "agent_tasks"

    task_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    agent_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        index=True,
    )
    task_type: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="pending",
        index=True,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        default=dict,
    )
    result: Mapped[Optional[dict[str, Any]]] = mapped_column(
        nullable=True,
    )
    error: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    timeout_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    retry_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
    )
    max_retries: Mapped[int] = mapped_column(
        default=3,
        nullable=False,
    )

    __table_args__ = (
        Index(
            "idx_agent_tasks_agent_status",
            "agent_id",
            "status",
        ),
        Index(
            "idx_agent_tasks_status",
            "status",
        ),
    )

    def __repr__(self) -> str:
        return f"AgentTask(task_id={self.task_id}, agent_id={self.agent_id}, status={self.status})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "task_type": self.task_type,
            "status": self.status,
            "payload": self.payload,
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "timeout_at": self.timeout_at.isoformat() if self.timeout_at else None,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
