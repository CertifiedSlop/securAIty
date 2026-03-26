"""
Incident Model

Model for tracking security incidents and their lifecycle.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from sqlalchemy import BigInteger, DateTime, Enum as SQLEnum, ForeignKey, Index, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

from securAIty.storage.models.base import Base, TimestampMixin


class IncidentStatus(str, Enum):
    """Incident lifecycle status."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ESCALATED = "escalated"


class IncidentSeverity(str, Enum):
    """Incident severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentPriority(str, Enum):
    """Incident priority levels."""

    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class Incident(Base, TimestampMixin):
    """
    Security incident entity.

    Tracks security incidents from detection through resolution.

    Attributes:
        incident_id: Primary key
        title: Incident title
        description: Detailed description
        severity: Incident severity
        status: Current status
        priority: Response priority
        timeline: Timeline of events
        assigned_to: Assigned responder
        root_cause: Root cause analysis
        resolution: Resolution details
    """

    __tablename__ = "incidents"

    incident_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    severity: Mapped[str] = mapped_column(
        SQLEnum(IncidentSeverity, name="incident_severity_enum"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        SQLEnum(IncidentStatus, name="incident_status_enum"),
        nullable=False,
        default=IncidentStatus.OPEN,
        index=True,
    )
    priority: Mapped[str] = mapped_column(
        SQLEnum(IncidentPriority, name="incident_priority_enum"),
        nullable=False,
        default=IncidentPriority.P3,
    )
    timeline: Mapped[dict[str, Any]] = mapped_column(
        default=list,
    )
    assigned_to: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    contained_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    root_cause: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    resolution: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    related_event_ids: Mapped[list[int]] = mapped_column(
        default=list,
    )
    tags: Mapped[list[str]] = mapped_column(
        default=list,
    )
    external_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        index=True,
    )
    source_system: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "idx_incidents_status_severity",
            "status",
            "severity",
        ),
        Index(
            "idx_incidents_detected_at",
            "detected_at",
        ),
        Index(
            "idx_incidents_assigned",
            "assigned_to",
            "status",
        ),
    )

    def __repr__(self) -> str:
        return f"Incident(incident_id={self.incident_id}, title={self.title}, status={self.status})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, IncidentSeverity) else self.severity,
            "status": self.status.value if isinstance(self.status, IncidentStatus) else self.status,
            "priority": self.priority.value if isinstance(self.priority, IncidentPriority) else self.priority,
            "timeline": self.timeline,
            "assigned_to": self.assigned_to,
            "detected_at": self.detected_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "contained_at": self.contained_at.isoformat() if self.contained_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "root_cause": self.root_cause,
            "resolution": self.resolution,
            "related_event_ids": self.related_event_ids,
            "tags": self.tags,
            "external_id": self.external_id,
            "source_system": self.source_system,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def add_timeline_entry(self, entry: str, entry_type: str = "note") -> None:
        timeline_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": entry_type,
            "entry": entry,
        }
        if not isinstance(self.timeline, list):
            self.timeline = []
        self.timeline.append(timeline_entry)


class IncidentNote(Base, TimestampMixin):
    """
    Incident notes for collaboration.

    Attributes:
        note_id: Primary key
        incident_id: Foreign key to incident
        content: Note content
        author: Note author
    """

    __tablename__ = "incident_notes"

    note_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    incident_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    author: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    is_internal: Mapped[bool] = mapped_column(
        default=True,
        nullable=False,
    )

    __table_args__ = (
        Index(
            "idx_incident_notes_incident",
            "incident_id",
            "created_at",
        ),
    )

    def __repr__(self) -> str:
        return f"IncidentNote(note_id={self.note_id}, incident_id={self.incident_id})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "note_id": self.note_id,
            "incident_id": self.incident_id,
            "content": self.content,
            "author": self.author,
            "is_internal": self.is_internal,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
