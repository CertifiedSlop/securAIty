from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class IncidentStatus(str):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentPriority(str):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentCategory(str):
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class IncidentBase(BaseModel):
    title: str = Field(min_length=1, max_length=500, description="Brief title describing the incident")
    description: str = Field(min_length=1, max_length=10000, description="Detailed description of the incident")
    category: IncidentCategory = Field(description="Category of the incident")
    priority: IncidentPriority = Field(description="Priority level for response")
    status: IncidentStatus = Field(default=IncidentStatus.NEW, description="Current status of the incident")

    model_config = ConfigDict(from_attributes=True)


class IncidentCreate(IncidentBase):
    assigned_to: Optional[str] = Field(default=None, max_length=255, description="User or team assigned to the incident")
    related_event_ids: Optional[List[UUID]] = Field(default=None, description="IDs of related security events")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=500, description="Updated title")
    description: Optional[str] = Field(default=None, min_length=1, max_length=10000, description="Updated description")
    category: Optional[IncidentCategory] = Field(default=None, description="Updated category")
    priority: Optional[IncidentPriority] = Field(default=None, description="Updated priority")
    status: Optional[IncidentStatus] = Field(default=None, description="Updated status")
    assigned_to: Optional[str] = Field(default=None, max_length=255, description="Updated assignee")
    resolution_notes: Optional[str] = Field(default=None, max_length=5000, description="Notes on resolution")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Updated metadata")

    model_config = ConfigDict(from_attributes=True)


class IncidentResponse(IncidentBase):
    id: UUID = Field(description="Unique identifier for the incident")
    assigned_to: Optional[str] = Field(default=None, description="User or team assigned to the incident")
    related_event_ids: List[UUID] = Field(default_factory=list, description="IDs of related security events")
    created_at: datetime = Field(description="When the incident was created")
    updated_at: Optional[datetime] = Field(default=None, description="When the incident was last updated")
    resolved_at: Optional[datetime] = Field(default=None, description="When the incident was resolved")
    resolution_notes: Optional[str] = Field(default=None, description="Notes on how the incident was resolved")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Incident metadata")

    model_config = ConfigDict(from_attributes=True)


class IncidentFilter(BaseModel):
    status: Optional[IncidentStatus] = Field(default=None, description="Filter by status")
    priority: Optional[IncidentPriority] = Field(default=None, description="Filter by priority")
    category: Optional[IncidentCategory] = Field(default=None, description="Filter by category")
    assigned_to: Optional[str] = Field(default=None, description="Filter by assignee")
    search: Optional[str] = Field(default=None, max_length=255, description="Search in title and description")
    start_date: Optional[datetime] = Field(default=None, description="Filter incidents from this date")
    end_date: Optional[datetime] = Field(default=None, description="Filter incidents until this date")

    model_config = ConfigDict(from_attributes=True)
