from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class AgentStatus(str):
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"


class AgentType(str):
    THREAT_DETECTION = "threat_detection"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    INCIDENT_RESPONSE = "incident_response"
    LOG_ANALYZER = "log_analyzer"
    COMPLIANCE_CHECKER = "compliance_checker"
    MALWARE_ANALYZER = "malware_analyzer"
    NETWORK_MONITOR = "network_monitor"
    CUSTOM = "custom"


class AgentCapabilities(BaseModel):
    supported_event_types: List[str] = Field(default_factory=list, description="Event types this agent can handle")
    max_concurrent_tasks: int = Field(default=5, ge=1, description="Maximum concurrent tasks the agent can handle")
    supported_actions: List[str] = Field(default_factory=list, description="Actions the agent can perform")
    version: str = Field(description="Agent version")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional capability metadata")

    model_config = ConfigDict(from_attributes=True)


class AgentBase(BaseModel):
    name: str = Field(min_length=1, max_length=255, description="Human-readable agent name")
    agent_type: AgentType = Field(description="Type of security agent")
    description: str = Field(min_length=1, max_length=1000, description="Agent description")

    model_config = ConfigDict(from_attributes=True)


class AgentRegister(AgentBase):
    capabilities: AgentCapabilities = Field(description="Agent capabilities and configuration")
    host: str = Field(min_length=1, max_length=255, description="Host where the agent is running")
    port: Optional[int] = Field(default=None, ge=1, le=65535, description="Port for agent communication")


class AgentResponse(AgentBase):
    id: UUID = Field(description="Unique identifier for the agent")
    status: AgentStatus = Field(description="Current agent status")
    capabilities: AgentCapabilities = Field(description="Agent capabilities")
    host: str = Field(description="Host where the agent is running")
    port: Optional[int] = Field(default=None, description="Port for agent communication")
    registered_at: datetime = Field(description="When the agent was registered")
    last_heartbeat: Optional[datetime] = Field(default=None, description="Last heartbeat timestamp")

    model_config = ConfigDict(from_attributes=True)


class AgentHeartbeat(BaseModel):
    status: AgentStatus = Field(description="Current agent status")
    cpu_usage: Optional[float] = Field(default=None, ge=0, le=100, description="CPU usage percentage")
    memory_usage: Optional[float] = Field(default=None, ge=0, le=100, description="Memory usage percentage")
    active_tasks: int = Field(default=0, ge=0, description="Number of currently active tasks")
    completed_tasks: int = Field(default=0, ge=0, description="Total completed tasks")
    failed_tasks: int = Field(default=0, ge=0, description="Total failed tasks")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional heartbeat data")

    model_config = ConfigDict(from_attributes=True)


class AgentStatusResponse(BaseModel):
    agent_id: UUID = Field(description="Agent unique identifier")
    status: AgentStatus = Field(description="Current agent status")
    last_heartbeat: datetime = Field(description="Last heartbeat timestamp")
    cpu_usage: Optional[float] = Field(default=None, description="CPU usage percentage")
    memory_usage: Optional[float] = Field(default=None, description="Memory usage percentage")
    active_tasks: int = Field(description="Number of currently active tasks")
    health_score: float = Field(ge=0, le=100, description="Overall health score (0-100)")
    is_responsive: bool = Field(description="Whether the agent is responding to heartbeats")

    model_config = ConfigDict(from_attributes=True)
