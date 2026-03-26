"""
Event Handler Registry

Provides handler registration, discovery, and execution for
security events with support for filtering and prioritization.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .schema import EventType, SecurityEvent, Severity


class EventHandler(ABC):
    """
    Abstract base class for security event handlers.

    Handlers process specific event types and can be registered
    with the event bus for automatic invocation.

    Subclasses must implement handle() with their event processing logic.
    """

    @property
    @abstractmethod
    def handled_event_types(self) -> list[EventType]:
        """
        Return list of event types this handler processes.

        Returns:
            List of EventType enums this handler subscribes to
        """
        pass

    @property
    def priority(self) -> int:
        """
        Handler priority for ordering (lower = higher priority).

        Returns:
            Priority value, default 100
        """
        return 100

    @property
    def name(self) -> str:
        """
        Human-readable handler name.

        Returns:
            Handler class name by default
        """
        return self.__class__.__name__

    @abstractmethod
    async def handle(self, event: SecurityEvent) -> None:
        """
        Process the security event.

        Args:
            event: Security event to process

        Raises:
            Exception: Handler-specific exceptions
        """
        pass

    async def on_success(self, event: SecurityEvent) -> None:
        """
        Callback for successful event processing.

        Args:
            event: Successfully processed event
        """
        pass

    async def on_error(self, event: SecurityEvent, error: Exception) -> None:
        """
        Callback for failed event processing.

        Args:
            event: Failed event
            error: Exception that was raised
        """
        pass


@dataclass
class HandlerRegistration:
    """
    Registration metadata for an event handler.

    Attributes:
        handler: Handler instance
        event_types: Event types handled
        priority: Execution priority
        name: Handler identifier
        enabled: Whether handler is active
        max_retries: Maximum retry attempts on failure
        timeout_seconds: Execution timeout
    """

    handler: EventHandler
    event_types: list[EventType]
    priority: int
    name: str
    enabled: bool = True
    max_retries: int = 3
    timeout_seconds: float = 30.0

    @classmethod
    def from_handler(cls, handler: EventHandler) -> "HandlerRegistration":
        """
        Create registration from handler instance.

        Args:
            handler: Handler to register

        Returns:
            New HandlerRegistration instance
        """
        return cls(
            handler=handler,
            event_types=handler.handled_event_types,
            priority=handler.priority,
            name=handler.name,
        )


class EventHandlerRegistry:
    """
    Central registry for event handlers.

    Manages handler lifecycle, provides discovery by event type,
    and handles execution with retry and timeout semantics.
    Supports priority-based handler execution and async handler invocation.

    Attributes:
        _handlers: Registered handlers by name
        _event_handlers: Event type to handlers mapping
        _default_timeout: Default execution timeout
        _default_retries: Default retry count
    """

    def __init__(
        self,
        default_timeout: float = 30.0,
        default_retries: int = 3,
    ) -> None:
        """
        Initialize handler registry.

        Args:
            default_timeout: Default handler execution timeout
            default_retries: Default retry count on failure
        """
        self._handlers: dict[str, HandlerRegistration] = {}
        self._event_handlers: dict[EventType, list[HandlerRegistration]] = {}
        self._default_timeout = default_timeout
        self._default_retries = default_retries
        self._lock = asyncio.Lock()

    def register(
        self,
        handler: EventHandler,
        event_types: Optional[list[EventType]] = None,
        priority: Optional[int] = None,
        max_retries: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
    ) -> str:
        """
        Register a handler for event processing.

        Handlers are sorted by priority within each event type,
        with lower priority values executing first.

        Args:
            handler: Handler instance to register
            event_types: Override handled event types
            priority: Override execution priority
            max_retries: Override retry count
            timeout_seconds: Override execution timeout

        Returns:
            Handler registration name

        Raises:
            ValueError: If handler already registered
        """
        handler_name = handler.name

        if handler_name in self._handlers:
            raise ValueError(f"Handler '{handler_name}' already registered")

        registration = HandlerRegistration(
            handler=handler,
            event_types=event_types or handler.handled_event_types,
            priority=priority if priority is not None else handler.priority,
            name=handler_name,
            max_retries=max_retries if max_retries is not None else self._default_retries,
            timeout_seconds=timeout_seconds
            if timeout_seconds is not None
            else self._default_timeout,
        )

        self._handlers[handler_name] = registration

        for event_type in registration.event_types:
            if event_type not in self._event_handlers:
                self._event_handlers[event_type] = []
            self._event_handlers[event_type].append(registration)
            self._event_handlers[event_type].sort(key=lambda h: h.priority)

        return handler_name

    def unregister(self, handler_name: str) -> bool:
        """
        Remove handler from registry.

        Args:
            handler_name: Handler name to remove

        Returns:
            True if handler was removed, False if not found
        """
        if handler_name not in self._handlers:
            return False

        registration = self._handlers.pop(handler_name)

        for event_type in registration.event_types:
            if event_type in self._event_handlers:
                self._event_handlers[event_type] = [
                    handler_reg
                    for handler_reg in self._event_handlers[event_type]
                    if handler_reg.name != handler_name
                ]

        return True

    def get_handlers_for_event(
        self,
        event: SecurityEvent,
    ) -> list[HandlerRegistration]:
        """
        Get all handlers applicable to an event.

        Returns handlers sorted by priority (lower values first).

        Args:
            event: Event to find handlers for

        Returns:
            List of handler registrations sorted by priority
        """
        handlers = self._event_handlers.get(event.event_type, [])
        return [handler_reg for handler_reg in handlers if handler_reg.enabled]

    def get_handler(
        self,
        handler_name: str,
    ) -> Optional[HandlerRegistration]:
        """
        Get handler by name.

        Args:
            handler_name: Handler name

        Returns:
            Handler registration or None if not found
        """
        return self._handlers.get(handler_name)

    def list_handlers(self) -> list[HandlerRegistration]:
        """
        Get all registered handlers.

        Returns:
            List of all handler registrations
        """
        return list(self._handlers.values())

    def list_handlers_for_event_type(self, event_type: EventType) -> list[str]:
        """
        Get handler names for an event type.

        Args:
            event_type: Event type to query

        Returns:
            List of handler names
        """
        handlers = self._event_handlers.get(event_type, [])
        return [handler_reg.name for handler_reg in handlers]

    async def dispatch(self, event: SecurityEvent) -> dict[str, Any]:
        """
        Dispatch event to all applicable handlers.

        Handlers are executed in priority order with retry and
        timeout semantics applied to each handler.

        Args:
            event: Event to dispatch

        Returns:
            Dictionary of handler results {name: success/error}
        """
        handlers = self.get_handlers_for_event(event)
        results: dict[str, Any] = {}

        async with self._lock:
            for registration in handlers:
                result = await self._execute_handler(registration, event)
                results[registration.name] = result

        return results

    async def _execute_handler(
        self,
        registration: HandlerRegistration,
        event: SecurityEvent,
    ) -> dict[str, Any]:
        """
        Execute a single handler with retry and timeout.

        Implements exponential backoff between retry attempts.

        Args:
            registration: Handler registration
            event: Event to process

        Returns:
            Execution result with success status and metadata
        """
        handler = registration.handler
        max_retries = registration.max_retries
        timeout = registration.timeout_seconds

        for attempt in range(max_retries):
            try:
                async with asyncio.timeout(timeout):
                    await handler.handle(event)

                await handler.on_success(event)
                return {"success": True, "attempts": attempt + 1}

            except asyncio.TimeoutError as exception:
                if attempt == max_retries - 1:
                    await handler.on_error(event, exception)
                    return {
                        "success": False,
                        "error": "timeout",
                        "message": f"Handler timed out after {timeout}s",
                        "attempts": attempt + 1,
                    }

            except Exception as exception:
                if attempt == max_retries - 1:
                    await handler.on_error(event, exception)
                    return {
                        "success": False,
                        "error": type(exception).__name__,
                        "message": str(exception),
                        "attempts": attempt + 1,
                    }

                backoff_delay = 0.1 * (2**attempt)
                await asyncio.sleep(backoff_delay)

        return {"success": False, "error": "max_retries_exceeded", "attempts": max_retries}

    def enable_handler(self, handler_name: str) -> bool:
        """
        Enable a disabled handler.

        Args:
            handler_name: Handler name

        Returns:
            True if enabled, False if not found
        """
        if handler_name in self._handlers:
            self._handlers[handler_name].enabled = True
            return True
        return False

    def disable_handler(self, handler_name: str) -> bool:
        """
        Disable a handler without removing it.

        Args:
            handler_name: Handler name

        Returns:
            True if disabled, False if not found
        """
        if handler_name in self._handlers:
            self._handlers[handler_name].enabled = False
            return True
        return False


class AsyncHandlerWrapper(EventHandler):
    """
    Wrapper for converting async functions to handlers.

    Enables quick handler creation from standalone async functions
    without defining a full class.
    """

    def __init__(
        self,
        event_types: list[EventType],
        handler_func: Callable[[SecurityEvent], Any],
        name: Optional[str] = None,
        priority: int = 100,
    ) -> None:
        """
        Initialize wrapper with function and event types.

        Args:
            event_types: Event types to handle
            handler_func: Async function to call
            name: Optional handler name
            priority: Execution priority
        """
        self._event_types = event_types
        self._handler_func = handler_func
        self._name = name or handler_func.__name__
        self._priority = priority

    @property
    def handled_event_types(self) -> list[EventType]:
        return self._event_types

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    async def handle(self, event: SecurityEvent) -> None:
        await self._handler_func(event)


HandlerRegistry = EventHandlerRegistry
