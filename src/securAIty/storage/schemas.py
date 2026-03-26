"""
Storage Schemas

Pydantic schemas for request/response validation in the storage layer.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict


class EventTypeEnum(str, Enum):
    """Security event types."""

    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHORIZATION_FAILURE = "authorization_failure"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SYSTEM_ERROR = "system_error"
    CONFIGURATION_CHANGE = "configuration_change"
    THREAT_DETECTED = "threat_detected"
    POLICY_VIOLATION = "policy_violation"
    CUSTOM = "custom"


class SeverityLevelEnum(str, Enum):
    """Severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatusEnum(str, Enum):
    """Incident status."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ESCALATED = "escalated"


class IncidentSeverityEnum(str, Enum):
    """Incident severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentPriorityEnum(str, Enum):
    """Incident priority."""

    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class AgentTypeEnum(str, Enum):
    """Agent types."""

    DETECTOR = "detector"
    ANALYZER = "analyzer"
    RESPONDER = "responder"
    COLLECTOR = "collector"
    ENRICHER = "enricher"
    CUSTOM = "custom"


class AgentStatusEnum(str, Enum):
    """Agent status."""

    IDLE = "idle"
    RUNNING = "running"
    BUSY = "busy"
    PAUSED = "paused"
    ERROR = "error"
    STOPPED = "stopped"
    UNREACHABLE = "unreachable"


class ActionTypeEnum(str, Enum):
    """Audit action types."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    ACCESS = "access"
    MODIFY = "modify"
    CONFIGURE = "configure"
    AUTHENTICATE = "authenticate"
    AUTHORIZE = "authorize"
    EXPORT = "export"
    IMPORT = "import"
    CUSTOM = "custom"


class AuditStatusEnum(str, Enum):
    """Audit status."""

    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"
    PARTIAL = "partial"


class SecurityEventBase(BaseModel):
    """Base schema for security events."""

    event_type: EventTypeEnum
    severity: SeverityLevelEnum
    source: str = Field(..., max_length=255)
    title: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    actor_id: Optional[str] = Field(None, max_length=255)
    correlation_id: Optional[str] = Field(None, max_length=255)
    resource_id: Optional[str] = Field(None, max_length=255)
    resource_type: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    user_agent: Optional[str] = Field(None, max_length=500)


class SecurityEventCreate(SecurityEventBase):
    """Schema for creating security events."""

    pass


class SecurityEventUpdate(BaseModel):
    """Schema for updating security events."""

    processed: Optional[bool] = None
    title: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = None


class SecurityEventResponse(SecurityEventBase):
    """Schema for security event responses."""

    model_config = ConfigDict(from_attributes=True)

    event_id: int
    timestamp: datetime
    processed: bool
    created_at: datetime
    updated_at: datetime


class IncidentBase(BaseModel):
    """Base schema for incidents."""

    title: str = Field(..., max_length=500)
    description: Optional[str] = None
    severity: IncidentSeverityEnum
    priority: Optional[IncidentPriorityEnum] = IncidentPriorityEnum.P3
    assigned_to: Optional[str] = Field(None, max_length=255)
    tags: List[str] = Field(default_factory=list)
    external_id: Optional[str] = Field(None, max_length=255)
    source_system: Optional[str] = Field(None, max_length=255)


class IncidentCreate(IncidentBase):
    """Schema for creating incidents."""

    related_event_ids: List[int] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    """Schema for updating incidents."""

    title: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = None
    severity: Optional[IncidentSeverityEnum] = None
    status: Optional[IncidentStatusEnum] = None
    priority: Optional[IncidentPriorityEnum] = None
    assigned_to: Optional[str] = Field(None, max_length=255)
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    tags: Optional[List[str]] = None


class IncidentResponse(IncidentBase):
    """Schema for incident responses."""

    model_config = ConfigDict(from_attributes=True)

    incident_id: int
    status: IncidentStatusEnum
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    detected_at: datetime
    acknowledged_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    related_event_ids: List[int]
    created_at: datetime
    updated_at: datetime


class IncidentNoteBase(BaseModel):
    """Base schema for incident notes."""

    content: str
    author: str = Field(..., max_length=255)
    is_internal: bool = True


class IncidentNoteCreate(IncidentNoteBase):
    """Schema for creating incident notes."""

    pass


class IncidentNoteResponse(IncidentNoteBase):
    """Schema for incident note responses."""

    model_config = ConfigDict(from_attributes=True)

    note_id: int
    incident_id: int
    created_at: datetime
    updated_at: datetime


class AgentBase(BaseModel):
    """Base schema for agents."""

    name: str = Field(..., max_length=255)
    agent_type: AgentTypeEnum
    version: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    config: Dict[str, Any] = Field(default_factory=dict)
    host: Optional[str] = Field(None, max_length=255)
    port: Optional[int] = None
    endpoint: Optional[str] = Field(None, max_length=500)


class AgentCreate(AgentBase):
    """Schema for creating agents."""

    pass


class AgentUpdate(BaseModel):
    """Schema for updating agents."""

    status: Optional[AgentStatusEnum] = None
    version: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    capabilities: Optional[List[str]] = None
    config: Optional[Dict[str, Any]] = None
    last_error: Optional[str] = None


class AgentResponse(AgentBase):
    """Schema for agent responses."""

    model_config = ConfigDict(from_attributes=True)

    agent_id: int
    status: AgentStatusEnum
    metadata: Dict[str, Any]
    last_heartbeat: Optional[datetime] = None
    registered_at: datetime
    last_error: Optional[str] = None
    last_error_at: Optional[datetime] = None
    tasks_completed: int
    tasks_failed: int
    created_at: datetime
    updated_at: datetime


class AgentTaskBase(BaseModel):
    """Base schema for agent tasks."""

    task_type: str = Field(..., max_length=255)
    payload: Dict[str, Any] = Field(default_factory=dict)


class AgentTaskCreate(AgentTaskBase):
    """Schema for creating agent tasks."""

    agent_id: int
    timeout_seconds: Optional[int] = None


class AgentTaskUpdate(BaseModel):
    """Schema for updating agent tasks."""

    status: Optional[str] = Field(None, max_length=50)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class AgentTaskResponse(AgentTaskBase):
    """Schema for agent task responses."""

    model_config = ConfigDict(from_attributes=True)

    task_id: int
    agent_id: int
    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    timeout_at: Optional[datetime] = None
    retry_count: int
    max_retries: int
    created_at: datetime
    updated_at: datetime


class AuditLogBase(BaseModel):
    """Base schema for audit logs."""

    action: ActionTypeEnum
    actor: str = Field(..., max_length=255)
    actor_type: str = Field(default="user", max_length=100)
    resource_type: str = Field(..., max_length=255)
    resource_id: Optional[str] = Field(None, max_length=255)
    resource_name: Optional[str] = Field(None, max_length=500)
    status: AuditStatusEnum = AuditStatusEnum.SUCCESS
    details: Dict[str, Any] = Field(default_factory=dict)
    changes: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    ip_address: Optional[str] = Field(None, max_length=45)
    user_agent: Optional[str] = Field(None, max_length=500)
    session_id: Optional[str] = Field(None, max_length=255)
    request_id: Optional[str] = Field(None, max_length=255)
    tenant_id: Optional[str] = Field(None, max_length=255)
    duration_ms: Optional[int] = None


class AuditLogCreate(AuditLogBase):
    """Schema for creating audit logs."""

    pass


class AuditLogResponse(AuditLogBase):
    """Schema for audit log responses."""

    model_config = ConfigDict(from_attributes=True)

    log_id: int
    timestamp: datetime
    created_at: datetime
    updated_at: datetime


class PaginationParams(BaseModel):
    """Pagination parameters."""

    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=1000)


class PaginatedResponse(BaseModel):
    """Paginated response wrapper."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    items: List[Any]
    total: int
    skip: int
    limit: int
