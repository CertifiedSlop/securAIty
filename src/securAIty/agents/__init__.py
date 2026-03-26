"""
Agents Package

Security agents for threat detection, analysis, remediation,
and auditing with standardized interfaces.
"""

from .base import BaseAgent, AgentCapability, HealthStatus, TaskPriority, TaskRequest, TaskResult
from ..utils.config import AgentConfig
from enum import Enum

class AgentState(str, Enum):
    """Agent lifecycle state."""
    INITIALIZING = "initializing"
    READY = "ready"
    BUSY = "busy"
    STOPPING = "stopping"
    STOPPED = "stopped"

__all__ = [
    "BaseAgent",
    "AgentConfig",
    "AgentCapability",
    "AgentState",
    "HealthStatus",
    "TaskPriority",
    "TaskRequest",
    "TaskResult",
]
