from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict, field_validator


class EventSeverity(str):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str):
    SECURITY_ALERT = "security_alert"
    INTRUSION_DETECTED = "intrusion_detected"
    MALWARE_DETECTED = "malware_detected"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_BREACH = "data_breach"
    POLICY_VIOLATION = "policy_violation"
    SYSTEM_ANOMALY = "system_anomaly"
    THREAT_INTELLIGENCE = "threat_intelligence"
    AUDIT_LOG = "audit_log"
    CUSTOM = "custom"


class EventBase(BaseModel):
    event_type: EventType = Field(description="Type of security event")
    severity: EventSeverity = Field(description="Severity level of the event")
    source: str = Field(min_length=1, max_length=255, description="Source system or component that generated the event")
    title: str = Field(min_length=1, max_length=500, description="Brief title describing the event")
    description: str = Field(min_length=1, max_length=5000, description="Detailed description of the event")

    model_config = ConfigDict(from_attributes=True)


class EventCreate(EventBase):
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata for the event")
    occurred_at: Optional[datetime] = Field(default=None, description="When the event occurred (defaults to now)")


class EventUpdate(BaseModel):
    severity: Optional[EventSeverity] = Field(default=None, description="Updated severity level")
    title: Optional[str] = Field(default=None, min_length=1, max_length=500, description="Updated title")
    description: Optional[str] = Field(default=None, min_length=1, max_length=5000, description="Updated description")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Updated metadata")
    status: Optional[str] = Field(default=None, description="Updated status")

    model_config = ConfigDict(from_attributes=True)


class EventResponse(EventBase):
    id: UUID = Field(description="Unique identifier for the event")
    status: str = Field(default="new", description="Current status of the event")
    occurred_at: datetime = Field(description="When the event occurred")
    created_at: datetime = Field(description="When the event was recorded")
    updated_at: Optional[datetime] = Field(default=None, description="When the event was last updated")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Event metadata")
    related_incident_id: Optional[UUID] = Field(default=None, description="ID of related incident if any")

    model_config = ConfigDict(from_attributes=True)


class EventFilter(BaseModel):
    event_type: Optional[EventType] = Field(default=None, description="Filter by event type")
    severity: Optional[EventSeverity] = Field(default=None, description="Filter by severity level")
    source: Optional[str] = Field(default=None, description="Filter by source system")
    status: Optional[str] = Field(default=None, description="Filter by status")
    start_date: Optional[datetime] = Field(default=None, description="Filter events from this date")
    end_date: Optional[datetime] = Field(default=None, description="Filter events until this date")
    search: Optional[str] = Field(default=None, max_length=255, description="Search in title and description")

    model_config = ConfigDict(from_attributes=True)
