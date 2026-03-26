"""
Correlation ID Management

Provides distributed tracing context management for correlating
security events across agents and system boundaries.
Implements thread-safe, async-compatible context tracking.
"""

import asyncio
import contextvars
import threading
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Iterator, Optional
from uuid import uuid4


@dataclass
class CorrelationContext:
    """
    Distributed tracing context for event correlation.

    Contains all identifiers needed to trace an event chain
    from initiation through all downstream processing.

    Attributes:
        correlation_id: Unique ID linking all related events
        causation_id: ID of the event that caused this chain
        span_id: Current operation span within the correlation
        trace_id: Root trace identifier for cross-system tracing
        baggage: Key-value pairs for cross-cutting context
        depth: Nesting level of correlated operations
        parent_context: Optional parent context for nested correlations
    """

    correlation_id: str
    causation_id: Optional[str] = None
    span_id: str = field(default_factory=lambda: str(uuid4()))
    trace_id: Optional[str] = None
    baggage: dict[str, str] = field(default_factory=dict)
    depth: int = 0
    parent_context: Optional["CorrelationContext"] = None

    @classmethod
    def new(
        cls,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        baggage: Optional[dict[str, str]] = None,
    ) -> "CorrelationContext":
        """
        Create a new root correlation context.

        Args:
            correlation_id: Optional pre-existing correlation ID
            causation_id: Optional causing event ID
            trace_id: Optional external trace ID
            baggage: Optional cross-cutting context

        Returns:
            New root correlation context
        """
        return cls(
            correlation_id=correlation_id or str(uuid4()),
            causation_id=causation_id,
            trace_id=trace_id,
            baggage=baggage or {},
            depth=0,
        )

    def create_child(
        self,
        baggage: Optional[dict[str, str]] = None,
    ) -> "CorrelationContext":
        """
        Create child context for nested operations.

        Args:
            baggage: Additional baggage to merge

        Returns:
            New child context inheriting parent correlation
        """
        merged_baggage = {**self.baggage, **(baggage or {})}

        return CorrelationContext(
            correlation_id=self.correlation_id,
            causation_id=self.span_id,
            span_id=str(uuid4()),
            trace_id=self.trace_id or self.correlation_id,
            baggage=merged_baggage,
            depth=self.depth + 1,
            parent_context=self,
        )

    def with_baggage(self, key: str, value: str) -> "CorrelationContext":
        """
        Create new context with added baggage.

        Args:
            key: Baggage key
            value: Baggage value

        Returns:
            New context with merged baggage
        """
        new_baggage = {**self.baggage, key: value}
        return CorrelationContext(
            correlation_id=self.correlation_id,
            causation_id=self.causation_id,
            span_id=self.span_id,
            trace_id=self.trace_id,
            baggage=new_baggage,
            depth=self.depth,
            parent_context=self.parent_context,
        )

    def get_causation_chain(self) -> list[str]:
        """
        Get the chain of causation IDs.

        Returns:
            List of causation IDs from root to current
        """
        chain = []
        current_causation = self.causation_id
        parent = self.parent_context

        while current_causation is not None:
            chain.append(current_causation)
            if parent:
                current_causation = parent.causation_id
                parent = parent.parent_context
            else:
                break

        return list(reversed(chain))

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize context to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "baggage": self.baggage,
            "depth": self.depth,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CorrelationContext":
        """
        Deserialize context from dictionary.

        Args:
            data: Dictionary with context data

        Returns:
            Reconstructed context
        """
        return cls(
            correlation_id=data.get("correlation_id", str(uuid4())),
            causation_id=data.get("causation_id"),
            span_id=data.get("span_id", str(uuid4())),
            trace_id=data.get("trace_id"),
            baggage=data.get("baggage", {}),
            depth=data.get("depth", 0),
        )

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> "CorrelationContext":
        """
        Reconstruct context from transport headers.

        Args:
            headers: Header dictionary with correlation keys

        Returns:
            Context extracted from headers
        """
        baggage = {}
        for header_key, header_value in headers.items():
            if header_key.startswith("X-Baggage-"):
                baggage_key = header_key[10:]
                baggage[baggage_key] = header_value

        return cls(
            correlation_id=headers.get("X-Correlation-ID"),
            causation_id=headers.get("X-Causation-ID"),
            span_id=headers.get("X-Span-ID"),
            trace_id=headers.get("X-Trace-ID"),
            baggage=baggage,
        )

    def to_headers(self) -> dict[str, str]:
        """
        Convert context to transport headers.

        Returns:
            Header dictionary with correlation keys
        """
        headers = {
            "X-Correlation-ID": self.correlation_id,
            "X-Span-ID": self.span_id,
        }

        if self.causation_id:
            headers["X-Causation-ID"] = self.causation_id

        if self.trace_id:
            headers["X-Trace-ID"] = self.trace_id

        for baggage_key, baggage_value in self.baggage.items():
            headers[f"X-Baggage-{baggage_key}"] = baggage_value

        return headers


class CorrelationManager:
    """
    Thread-safe correlation ID management with async context support.

    Provides automatic correlation tracking across async call chains
    and thread boundaries using contextvars for async context and
    threading.local for thread context.

    Attributes:
        _async_context_var: Context variable for async storage
        _thread_local: Thread-local storage for sync context
        _contexts: Registry of active contexts by ID
    """

    _async_context_var: contextvars.ContextVar[Optional[CorrelationContext]] = (
        contextvars.ContextVar("correlation_context", default=None)
    )

    def __init__(self) -> None:
        """Initialize correlation manager with thread-safe storage."""
        self._contexts: dict[str, CorrelationContext] = {}
        self._async_lock = asyncio.Lock()
        self._thread_local = threading.local()

    def _get_thread_context(self) -> Optional[CorrelationContext]:
        """
        Get context from thread-local storage.

        Returns:
            Thread-local context or None
        """
        return getattr(self._thread_local, "context", None)

    def _set_thread_context(self, context: CorrelationContext) -> None:
        """
        Set context in thread-local storage.

        Args:
            context: Context to store
        """
        self._thread_local.context = context

    def _clear_thread_context(self) -> None:
        """Clear thread-local context."""
        if hasattr(self._thread_local, "context"):
            del self._thread_local.context

    def get_current(self) -> Optional[CorrelationContext]:
        """
        Get current context from async or thread context.

        Returns:
            Current context or None if not set
        """
        async_context = self._async_context_var.get()
        if async_context is not None:
            return async_context
        return self._get_thread_context()

    def set_current(self, context: CorrelationContext) -> None:
        """
        Set current context in async and thread context.

        Args:
            context: Context to set
        """
        self._async_context_var.set(context)
        self._set_thread_context(context)

    def clear_current(self) -> None:
        """Clear current context from async and thread context."""
        self._async_context_var.set(None)
        self._clear_thread_context()

    async def register_context(self, context: CorrelationContext) -> str:
        """
        Register context for global tracking.

        Thread-safe registration with async lock protection.

        Args:
            context: Context to register

        Returns:
            Correlation ID
        """
        async with self._async_lock:
            self._contexts[context.correlation_id] = context
        return context.correlation_id

    async def get_context(
        self,
        correlation_id: str,
    ) -> Optional[CorrelationContext]:
        """
        Get registered context by ID.

        Args:
            correlation_id: Correlation ID to lookup

        Returns:
            Context or None if not found
        """
        async with self._async_lock:
            return self._contexts.get(correlation_id)

    async def remove_context(self, correlation_id: str) -> bool:
        """
        Remove context from tracking.

        Args:
            correlation_id: ID to remove

        Returns:
            True if removed, False if not found
        """
        async with self._async_lock:
            if correlation_id in self._contexts:
                del self._contexts[correlation_id]
                return True
        return False

    def start_correlation(
        self,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        baggage: Optional[dict[str, str]] = None,
    ) -> CorrelationContext:
        """
        Start a new correlation.

        Args:
            correlation_id: Optional pre-existing ID
            causation_id: Optional causing event ID
            baggage: Optional initial baggage

        Returns:
            New root context, also set as current
        """
        context = CorrelationContext.new(
            correlation_id=correlation_id,
            causation_id=causation_id,
            baggage=baggage,
        )
        self.set_current(context)
        return context

    def continue_correlation(
        self,
        baggage: Optional[dict[str, str]] = None,
    ) -> CorrelationContext:
        """
        Continue current correlation with child context.

        Args:
            baggage: Additional baggage for child

        Returns:
            New child context, also set as current

        Raises:
            RuntimeError: If no current context exists
        """
        parent = self.get_current()
        if not parent:
            raise RuntimeError("No current correlation context")

        child = parent.create_child(baggage=baggage)
        self.set_current(child)
        return child

    def inject_correlation(
        self,
        correlation_id: str,
        causation_id: Optional[str] = None,
        baggage: Optional[dict[str, str]] = None,
    ) -> CorrelationContext:
        """
        Inject external correlation context.

        Args:
            correlation_id: External correlation ID
            causation_id: Optional causation ID
            baggage: Optional baggage

        Returns:
            New context set as current
        """
        context = CorrelationContext(
            correlation_id=correlation_id,
            causation_id=causation_id,
            baggage=baggage or {},
        )
        self.set_current(context)
        return context

    @contextmanager
    def correlation_scope(
        self,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        baggage: Optional[dict[str, str]] = None,
    ) -> Iterator[CorrelationContext]:
        """
        Context manager for automatic correlation lifecycle.

        Creates a new correlation context that is automatically
        cleaned up when exiting the context.

        Args:
            correlation_id: Optional pre-existing ID
            causation_id: Optional causing event ID
            baggage: Optional initial baggage

        Yields:
            Correlation context for the scope

        Example:
            >>> with manager.correlation_scope() as ctx:
            ...     # ctx is current correlation
            ...     process_event()
        """
        context = self.start_correlation(
            correlation_id=correlation_id,
            causation_id=causation_id,
            baggage=baggage,
        )
        try:
            yield context
        finally:
            self.clear_current()

    @asynccontextmanager
    async def async_correlation_scope(
        self,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        baggage: Optional[dict[str, str]] = None,
    ) -> AsyncIterator[CorrelationContext]:
        """
        Async context manager for automatic correlation lifecycle.

        Creates a new correlation context that is automatically
        cleaned up when exiting the async context.

        Args:
            correlation_id: Optional pre-existing ID
            causation_id: Optional causing event ID
            baggage: Optional initial baggage

        Yields:
            Correlation context for the scope

        Example:
            >>> async with manager.async_correlation_scope() as ctx:
            ...     # ctx is current correlation
            ...     await process_event()
        """
        context = self.start_correlation(
            correlation_id=correlation_id,
            causation_id=causation_id,
            baggage=baggage,
        )
        try:
            yield context
        finally:
            self.clear_current()

    @contextmanager
    def child_correlation_scope(
        self,
        baggage: Optional[dict[str, str]] = None,
    ) -> Iterator[CorrelationContext]:
        """
        Context manager for child correlation scope.

        Creates a child context from the current correlation
        and automatically restores parent on exit.

        Args:
            baggage: Additional baggage for child

        Yields:
            Child correlation context

        Raises:
            RuntimeError: If no parent context exists
        """
        parent = self.get_current()
        if not parent:
            raise RuntimeError("No parent correlation context")

        child = parent.create_child(baggage=baggage)
        self.set_current(child)
        try:
            yield child
        finally:
            self.set_current(parent)

    @asynccontextmanager
    async def async_child_correlation_scope(
        self,
        baggage: Optional[dict[str, str]] = None,
    ) -> AsyncIterator[CorrelationContext]:
        """
        Async context manager for child correlation scope.

        Creates a child context from the current correlation
        and automatically restores parent on exit.

        Args:
            baggage: Additional baggage for child

        Yields:
            Child correlation context

        Raises:
            RuntimeError: If no parent context exists
        """
        parent = self.get_current()
        if not parent:
            raise RuntimeError("No parent correlation context")

        child = parent.create_child(baggage=baggage)
        self.set_current(child)
        try:
            yield child
        finally:
            self.set_current(parent)

    def link_events(self, *contexts: CorrelationContext) -> list[str]:
        """
        Link multiple correlation contexts together.

        Creates causation chain between contexts for tracing
        related operations across system boundaries.

        Args:
            contexts: Contexts to link

        Returns:
            List of correlation IDs in link order
        """
        correlation_ids = []
        previous_context: Optional[CorrelationContext] = None

        for context in contexts:
            if previous_context:
                context.causation_id = previous_context.span_id
            correlation_ids.append(context.correlation_id)
            previous_context = context

        return correlation_ids


_correlation_manager: Optional[CorrelationManager] = None


def get_correlation_manager() -> CorrelationManager:
    """
    Get or create global correlation manager.

    Returns:
        Global correlation manager instance
    """
    global _correlation_manager
    if _correlation_manager is None:
        _correlation_manager = CorrelationManager()
    return _correlation_manager


def current_correlation() -> Optional[CorrelationContext]:
    """
    Get current correlation context.

    Returns:
        Current context or None
    """
    return get_correlation_manager().get_current()


def start_correlation(
    correlation_id: Optional[str] = None,
    causation_id: Optional[str] = None,
    baggage: Optional[dict[str, str]] = None,
) -> CorrelationContext:
    """
    Start new correlation.

    Args:
        correlation_id: Optional pre-existing ID
        causation_id: Optional causing event ID
        baggage: Optional initial baggage

    Returns:
        New root context
    """
    return get_correlation_manager().start_correlation(
        correlation_id=correlation_id,
        causation_id=causation_id,
        baggage=baggage,
    )


def continue_correlation(baggage: Optional[dict[str, str]] = None) -> CorrelationContext:
    """
    Continue current correlation.

    Args:
        baggage: Additional baggage

    Returns:
        Child context

    Raises:
        RuntimeError: If no current context
    """
    return get_correlation_manager().continue_correlation(baggage=baggage)


CorrelationTracker = CorrelationManager
