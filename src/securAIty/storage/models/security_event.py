"""
Security Event Model

Core model for tracking security events in the securAIty system.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from sqlalchemy import BigInteger, DateTime, Enum as SQLEnum, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from securAIty.storage.models.base import Base, TimestampMixin


class SeverityLevel(str, Enum):
    """Security event severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
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


class SecurityEvent(Base, TimestampMixin):
    """
    Security event entity.

    Tracks all security-related events in the system with full
    audit trail capabilities.

    Attributes:
        event_id: Primary key
        event_type: Type of security event
        severity: Severity level
        source: Event source identifier
        payload: Event data as JSON
        timestamp: When the event occurred
        processed: Whether the event has been processed
        correlation_id: ID for correlating related events
    """

    __tablename__ = "security_events"

    event_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    event_type: Mapped[str] = mapped_column(
        SQLEnum(EventType, name="event_type_enum"),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        SQLEnum(SeverityLevel, name="severity_level_enum"),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(500),
        nullable=True,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        default=dict,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    processed: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        index=True,
    )
    correlation_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    actor_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    resource_type: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "idx_security_events_composite",
            "event_type",
            "severity",
            "timestamp",
        ),
        Index(
            "idx_security_events_actor_timestamp",
            "actor_id",
            "timestamp",
        ),
        Index(
            "idx_security_events_resource",
            "resource_type",
            "resource_id",
        ),
    )

    def __repr__(self) -> str:
        return f"SecurityEvent(event_id={self.event_id}, event_type={self.event_type}, severity={self.severity})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value if isinstance(self.event_type, EventType) else self.event_type,
            "severity": self.severity.value if isinstance(self.severity, SeverityLevel) else self.severity,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "processed": self.processed,
            "correlation_id": self.correlation_id,
            "actor_id": self.actor_id,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
