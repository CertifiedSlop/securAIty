"""Event schema definitions for AI Security Manager."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
import uuid
import hashlib


class EventType(str, Enum):
    """Standard event types for security operations."""

    # Scanning events
    SECURITY_SCAN_INITIATED = "security.scan.initiated"
    SECURITY_SCAN_COMPLETED = "security.scan.completed"
    SECURITY_SCAN_FAILED = "security.scan.failed"

    # Threat detection events
    THREAT_DETECTED = "threat.detected"
    THREAT_ANALYZED = "threat.analyzed"
    THREAT_CONTAINED = "threat.contained"
    THREAT_ELIMINATED = "threat.eliminated"

    # Policy events
    POLICY_VIOLATION = "policy.violation"
    POLICY_UPDATED = "policy.updated"
    POLICY_EVALUATED = "policy.evaluated"

    # Incident events
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    INCIDENT_ASSIGNED = "incident.assigned"
    INCIDENT_RESOLVED = "incident.resolved"

    # Agent events
    AGENT_REGISTERED = "agent.registered"
    AGENT_UNREGISTERED = "agent.unregistered"
    AGENT_UNHEALTHY = "agent.unhealthy"
    AGENT_RECOVERED = "agent.recovered"

    # Configuration events
    CONFIG_CHANGED = "config.changed"
    CONFIG_RELOADED = "config.reloaded"

    # Audit events
    AUDIT_LOG_CREATED = "audit.log.created"
    AUDIT_LOG_ACCESSED = "audit.log.accessed"
    AUDIT_INTEGRITY_CHECK = "audit.integrity.check"


class Severity(str, Enum):
    """Event severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class EventContext:
    """Contextual information for event correlation."""

    user_id: Optional[str] = None
    resource_id: Optional[str] = None
    environment: str = "production"
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    custom: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "user_id": self.user_id,
            "resource_id": self.resource_id,
            "environment": self.environment,
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "custom": self.custom,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventContext":
        """Create from dictionary."""
        return cls(
            user_id=data.get("user_id"),
            resource_id=data.get("resource_id"),
            environment=data.get("environment", "production"),
            session_id=data.get("session_id"),
            ip_address=data.get("ip_address"),
            custom=data.get("custom", {}),
        )


@dataclass
class SecurityEvent:
    """Standard security event schema."""

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: str = ""
    event_type: EventType = EventType.SECURITY_SCAN_INITIATED
    severity: Severity = Severity.INFO
    correlation_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    context: EventContext = field(default_factory=EventContext)
    previous_hash: Optional[str] = None
    current_hash: Optional[str] = field(default=None, init=False)

    def __post_init__(self):
        """Calculate hash after initialization."""
        if self.current_hash is None:
            self.current_hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        """Calculate SHA256 hash of event for integrity verification."""
        content = f"{self.event_id}{self.timestamp.isoformat()}{self.source}{self.event_type.value}"
        if self.previous_hash:
            content = f"{content}{self.previous_hash}"
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
            "context": self.context.to_dict(),
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Create event from dictionary."""
        return cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            timestamp=(
                datetime.fromisoformat(data["timestamp"])
                if "timestamp" in data
                else datetime.utcnow()
            ),
            source=data.get("source", "unknown"),
            event_type=EventType(data.get("event_type", "security.scan.initiated")),
            severity=Severity(data.get("severity", "info")),
            correlation_id=data.get("correlation_id"),
            payload=data.get("payload", {}),
            context=EventContext.from_dict(data.get("context", {})),
            previous_hash=data.get("previous_hash"),
        )

    def with_correlation(self, correlation_id: str) -> "SecurityEvent":
        """Create a copy with correlation ID."""
        event = SecurityEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            source=self.source,
            event_type=self.event_type,
            severity=self.severity,
            correlation_id=correlation_id,
            payload=self.payload,
            context=self.context,
            previous_hash=self.previous_hash,
        )
        event.current_hash = self.current_hash
        return event

    def with_payload(self, **kwargs: Any) -> "SecurityEvent":
        """Create a copy with additional payload."""
        new_payload = {**self.payload, **kwargs}
        event = SecurityEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            source=self.source,
            event_type=self.event_type,
            severity=self.severity,
            correlation_id=self.correlation_id,
            payload=new_payload,
            context=self.context,
            previous_hash=self.previous_hash,
        )
        event.current_hash = self.current_hash
        return event
