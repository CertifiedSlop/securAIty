"""
Base agent module for AI Security Manager.

Defines core dataclasses and abstract base class for all security agents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid


class HealthStatus(str, Enum):
    """Agent health status enumeration."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class TaskPriority(int, Enum):
    """Task priority levels."""

    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 15


@dataclass
class AgentCapability:
    """
    Represents a capability that an agent can perform.

    Attributes:
        name: Unique identifier for the capability
        description: Human-readable description of what the capability does
        input_schema: JSON schema describing expected input format
        output_schema: JSON schema describing output format
        timeout: Maximum execution time in seconds
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    timeout: float = 30.0


@dataclass
class AgentMetadata:
    """
    Metadata describing an agent's identity and state.

    Attributes:
        agent_id: Unique identifier for the agent instance
        agent_type: Type/class of agent (e.g., 'threat_detector', 'policy_enforcer')
        version: Agent version string (semver format)
        capabilities: List of capabilities this agent provides
        health_status: Current health status of the agent
        created_at: Timestamp when agent was initialized
    """

    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_type: str = "base"
    version: str = "1.0.0"
    capabilities: list[AgentCapability] = field(default_factory=list)
    health_status: HealthStatus = HealthStatus.UNKNOWN
    created_at: datetime = field(default_factory=datetime.utcnow)

    def add_capability(self, capability: AgentCapability) -> None:
        """Add a capability to the agent."""
        self.capabilities.append(capability)

    def get_capability(self, name: str) -> Optional[AgentCapability]:
        """Get a capability by name."""
        for cap in self.capabilities:
            if cap.name == name:
                return cap
        return None


@dataclass
class TaskRequest:
    """
    Request to execute a task on an agent.

    Attributes:
        task_id: Unique identifier for the task
        capability: Name of the capability to execute
        input_data: Input data for the task
        priority: Task priority level
        correlation_id: ID to correlate related tasks
        timeout: Optional timeout override in seconds
    """

    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    capability: str = ""
    input_data: dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timeout: Optional[float] = None

    def __post_init__(self) -> None:
        if not self.capability:
            raise ValueError("TaskRequest must specify a capability")


@dataclass
class TaskResult:
    """
    Result from executing a task on an agent.

    Attributes:
        task_id: ID of the original task
        success: Whether the task completed successfully
        output_data: Output data from the task
        error_message: Error message if task failed
        execution_time_ms: Time taken to execute in milliseconds
        evidence: Supporting evidence or artifacts from execution
        timestamp: When the result was produced
    """

    task_id: str
    success: bool
    output_data: dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    execution_time_ms: float = 0.0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @classmethod
    def failure(
        cls,
        task_id: str,
        error_message: str,
        execution_time_ms: float = 0.0,
    ) -> "TaskResult":
        """Create a failed task result."""
        return cls(
            task_id=task_id,
            success=False,
            error_message=error_message,
            execution_time_ms=execution_time_ms,
        )

    @classmethod
    def success(
        cls,
        task_id: str,
        output_data: dict[str, Any],
        execution_time_ms: float = 0.0,
        evidence: Optional[list[dict[str, Any]]] = None,
    ) -> "TaskResult":
        """Create a successful task result."""
        return cls(
            task_id=task_id,
            success=True,
            output_data=output_data,
            execution_time_ms=execution_time_ms,
            evidence=evidence or [],
        )


class BaseAgent(ABC):
    """
    Abstract base class for all security agents.

    All agents must inherit from this class and implement the required
    async methods. Provides lifecycle management, capability execution,
    and health monitoring.
    """

    def __init__(self, agent_type: str = "base", version: str = "1.0.0") -> None:
        """
        Initialize the base agent.

        Args:
            agent_type: Type identifier for the agent
            version: Version string for the agent
        """
        self._metadata = AgentMetadata(
            agent_type=agent_type,
            version=version,
        )
        self._initialized = False

    @property
    def metadata(self) -> AgentMetadata:
        """Get the agent's metadata."""
        return self._metadata

    @property
    def agent_id(self) -> str:
        """Get the agent's unique ID."""
        return self._metadata.agent_id

    @property
    def is_initialized(self) -> bool:
        """Check if the agent has been initialized."""
        return self._initialized

    @abstractmethod
    async def initialize(self) -> None:
        """
        Initialize the agent and its capabilities.

        Called once when the agent is first registered with the orchestrator.
        Should set up resources, connections, and register capabilities.

        Raises:
            Exception: If initialization fails
        """
        pass

    @abstractmethod
    async def execute(self, request: TaskRequest) -> TaskResult:
        """
        Execute a task request.

        Called by the orchestrator to perform work. Must handle the
        specified capability and return appropriate results.

        Args:
            request: The task request containing capability and input data

        Returns:
            TaskResult with success status and output data
        """
        pass

    @abstractmethod
    async def health_check(self) -> HealthStatus:
        """
        Perform a health check on the agent.

        Should verify all critical components are functioning.
        Called periodically by the orchestrator.

        Returns:
            Current health status of the agent
        """
        pass

    @abstractmethod
    async def shutdown(self) -> None:
        """
        Gracefully shutdown the agent.

        Called when the agent is being unregistered or the system
        is shutting down. Should clean up resources and connections.
        """
        pass

    def get_metadata(self) -> AgentMetadata:
        """
        Get the agent's metadata.

        Returns:
            AgentMetadata containing agent identity and capabilities
        """
        return self._metadata

    def _update_health_status(self, status: HealthStatus) -> None:
        """Update the agent's health status."""
        self._metadata.health_status = status

    def _register_capability(self, capability: AgentCapability) -> None:
        """
        Register a capability with the agent.

        Args:
            capability: The capability to register
        """
        self._metadata.add_capability(capability)

    async def __aenter__(self) -> "BaseAgent":
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.shutdown()

    def __repr__(self) -> str:
        """String representation of the agent."""
        return f"{self.__class__.__name__}(id={self.agent_id}, type={self._metadata.agent_type})"
