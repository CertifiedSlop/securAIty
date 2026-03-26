"""
Audit Log Model

Model for tracking system audit logs and compliance data.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from sqlalchemy import BigInteger, DateTime, Enum as SQLEnum, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from securAIty.storage.models.base import Base, TimestampMixin


class ActionType(str, Enum):
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


class AuditStatus(str, Enum):
    """Audit entry status."""

    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"
    PARTIAL = "partial"


class AuditLog(Base, TimestampMixin):
    """
    Audit log entity.

    Comprehensive audit trail for compliance and forensics.

    Attributes:
        log_id: Primary key
        action: Action performed
        actor: Who performed the action
        status: Action status
        details: Detailed audit data
        ip_address: Source IP
        user_agent: Client user agent
    """

    __tablename__ = "audit_logs"

    log_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    action: Mapped[str] = mapped_column(
        SQLEnum(ActionType, name="audit_action_type_enum"),
        nullable=False,
        index=True,
    )
    actor: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    actor_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="user",
    )
    status: Mapped[str] = mapped_column(
        SQLEnum(AuditStatus, name="audit_status_enum"),
        nullable=False,
        default=AuditStatus.SUCCESS,
        index=True,
    )
    resource_type: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    resource_name: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        default=dict,
    )
    changes: Mapped[Optional[dict[str, Any]]] = mapped_column(
        nullable=True,
    )
    reason: Mapped[Optional[str]] = mapped_column(
        Text,
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
    session_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    request_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    duration_ms: Mapped[Optional[int]] = mapped_column(
        nullable=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index(
            "idx_audit_logs_actor_action",
            "actor",
            "action",
        ),
        Index(
            "idx_audit_logs_resource",
            "resource_type",
            "resource_id",
        ),
        Index(
            "idx_audit_logs_timestamp_status",
            "timestamp",
            "status",
        ),
        Index(
            "idx_audit_logs_tenant",
            "tenant_id",
            "timestamp",
        ),
    )

    def __repr__(self) -> str:
        return f"AuditLog(log_id={self.log_id}, action={self.action}, actor={self.actor}, status={self.status})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_id": self.log_id,
            "action": self.action.value if isinstance(self.action, ActionType) else self.action,
            "actor": self.actor,
            "actor_type": self.actor_type,
            "status": self.status.value if isinstance(self.status, AuditStatus) else self.status,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "details": self.details,
            "changes": self.changes,
            "reason": self.reason,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
