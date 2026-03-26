"""
Event System - Core event bus infrastructure for security events.

Provides async publish/subscribe via NATS, event schema definitions,
handler registry, and correlation ID tracking for distributed tracing.
"""

from .schema import (
    SecurityEvent,
    EventType,
    Severity,
    EventContext,
)
from .bus import EventBus, EventBusConfig
from .handlers import EventHandler, EventHandlerRegistry, HandlerRegistry
from .correlation import (
    CorrelationContext,
    CorrelationManager,
    CorrelationTracker,
    get_correlation_manager,
    current_correlation,
    start_correlation,
    continue_correlation,
)

__all__ = [
    "SecurityEvent",
    "EventType",
    "Severity",
    "EventContext",
    "EventBus",
    "EventBusConfig",
    "EventHandler",
    "EventHandlerRegistry",
    "HandlerRegistry",
    "CorrelationContext",
    "CorrelationManager",
    "CorrelationTracker",
    "get_correlation_manager",
    "current_correlation",
    "start_correlation",
    "continue_correlation",
]
