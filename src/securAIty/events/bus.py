"""
NATS Event Bus Implementation

Async publish/subscribe event bus using NATS for distributed
security event communication with JetStream persistence support.
"""

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any, Callable, Optional

import nats
from nats.aio.client import Client
from nats.errors import TimeoutError, ConnectionClosedError, NoServersError
from nats.js.api import StreamConfig, RetentionPolicy, StorageType

from .correlation import current_correlation
from .schema import SecurityEvent


class EventBusError(Exception):
    """Base exception for event bus errors."""

    pass


class EventBusConnectionError(EventBusError):
    """Raised when event bus connection fails."""

    pass


class EventBusPublishError(EventBusError):
    """Raised when event publish fails."""

    pass


class EventBusSubscribeError(EventBusError):
    """Raised when event subscription fails."""

    pass


class EventBusTimeoutError(EventBusError):
    """Raised when event bus operation times out."""

    pass


@dataclass
class EventBusConfig:
    """
    Configuration for NATS event bus connection.

    Attributes:
        servers: List of NATS server URLs
        cluster_id: NATS streaming cluster identifier
        client_id: Unique client identifier for this instance
        queue_group: Consumer group name for load balancing
        max_reconnect_attempts: Maximum reconnection attempts
        reconnect_delay: Base delay between reconnection attempts
        connection_timeout: Connection establishment timeout
        request_timeout: Request/response timeout
        jetstream_enabled: Enable JetStream for persistence
        jetstream_stream: JetStream stream name for events
        jetstream_storage_type: Storage type (memory/file)
        jetstream_retention: Retention policy for stream
        max_messages_per_subject: Max messages per subject
        max_age_seconds: Max age for messages in stream
    """

    servers: Optional[list[str]] = None
    cluster_id: str = "security-cluster"
    client_id: str = "security-manager"
    queue_group: str = "securAIty_events"
    max_reconnect_attempts: int = 10
    reconnect_delay: float = 2.0
    connection_timeout: float = 5.0
    request_timeout: float = 10.0
    jetstream_enabled: bool = True
    jetstream_stream: str = "SECURITY_EVENTS"
    jetstream_storage_type: str = "memory"
    jetstream_retention: str = "limits"
    max_messages_per_subject: int = 100000
    max_age_seconds: int = 86400

    def __post_init__(self) -> None:
        if self.servers is None:
            nats_url = os.getenv("NATS_URL", "nats://localhost:4222")
            self.servers = [nats_url]

        cluster_id = os.getenv("NATS_CLUSTER_ID")
        if cluster_id:
            self.cluster_id = cluster_id

        client_id = os.getenv("NATS_CLIENT_ID")
        if client_id:
            self.client_id = client_id

    @classmethod
    def from_environment(cls) -> "EventBusConfig":
        return cls()


class EventBus:
    """
    Async event bus for security event publish/subscribe.

    Provides reliable event distribution using NATS with optional
    JetStream persistence, automatic reconnection, and backpressure
    handling for high-throughput security monitoring.

    Attributes:
        config: Bus configuration settings
        _client: NATS client connection
        _subscriptions: Active subscription handles
        _is_connected: Connection state flag
        _reconnect_count: Current reconnection attempt count
        _jetstream_context: JetStream context if enabled
    """

    def __init__(self, config: Optional[EventBusConfig] = None) -> None:
        """
        Initialize event bus with configuration.

        Args:
            config: Optional custom configuration
        """
        self.config = config or EventBusConfig()
        self._client: Optional[Client] = None
        self._subscriptions: dict[str, Any] = {}
        self._is_connected = False
        self._reconnect_count = 0
        self._connection_lock = asyncio.Lock()
        self._pending_tasks: set[asyncio.Task] = set()
        self._jetstream_context: Optional[Any] = None
        self._error_handlers: list[Callable[[Exception], Any]] = []

    async def connect(self) -> None:
        """
        Establish connection to NATS servers.

        Implements exponential backoff for reconnection attempts
        and configures disconnect/reconnect callbacks for monitoring.

        Raises:
            EventBusConnectionError: If connection fails after max attempts
        """
        async with self._connection_lock:
            if self._is_connected:
                return

            servers = self.config.servers
            max_attempts = self.config.max_reconnect_attempts

            for attempt in range(max_attempts):
                try:
                    self._client = await nats.connect(
                        servers=servers[0] if len(servers) == 1 else servers,
                        connect_timeout=self.config.connection_timeout,
                        reconnect_time_wait=self.config.reconnect_delay,
                        max_reconnect_attempts=max_attempts,
                        disconnected_cb=self._handle_disconnect,
                        reconnected_cb=self._handle_reconnect,
                        closed_cb=self._handle_closed,
                        error_cb=self._handle_error,
                    )

                    if self.config.jetstream_enabled:
                        self._jetstream_context = self._client.jetstream()
                        try:
                            await self._jetstream_context.stream_info(
                                self.config.jetstream_stream
                            )
                        except Exception:
                            storage_type = (
                                StorageType.MEMORY
                                if self.config.jetstream_storage_type == "memory"
                                else StorageType.FILE
                            )
                            retention_policy = (
                                RetentionPolicy.LIMITS
                                if self.config.jetstream_retention == "limits"
                                else RetentionPolicy.INTEREST
                            )
                            await self._jetstream_context.add_stream(
                                name=self.config.jetstream_stream,
                                subjects=[f"{self.config.jetstream_stream}.*"],
                                storage=storage_type,
                                retention=retention_policy,
                                max_msgs_per_subject=self.config.max_messages_per_subject,
                                max_age=self.config.max_age_seconds * 1_000_000_000,
                            )

                    self._is_connected = True
                    self._reconnect_count = 0
                    return

                except (NoServersError, ConnectionClosedError) as e:
                    self._reconnect_count = attempt + 1
                    if attempt == max_attempts - 1:
                        error_msg = (
                            f"Failed to connect to NATS after {max_attempts} attempts"
                        )
                        raise EventBusConnectionError(error_msg) from e

                    backoff_delay = self.config.reconnect_delay * (2**attempt)
                    await asyncio.sleep(backoff_delay)
                except Exception as e:
                    self._reconnect_count = attempt + 1
                    if attempt == max_attempts - 1:
                        error_msg = (
                            f"Failed to connect to NATS after {max_attempts} attempts"
                        )
                        raise EventBusConnectionError(error_msg) from e
                    backoff_delay = self.config.reconnect_delay * (2**attempt)
                    await asyncio.sleep(backoff_delay)

    async def disconnect(self) -> None:
        """
        Gracefully close NATS connection.

        Cancels pending tasks and drains subscriptions before
        closing the connection.
        """
        async with self._connection_lock:
            if not self._is_connected:
                return

            for task in self._pending_tasks:
                task.cancel()

            self._pending_tasks.clear()

            for sub in self._subscriptions.values():
                await sub.unsubscribe()

            self._subscriptions.clear()

            if self._client:
                await self._client.drain()
                await self._client.close()

            self._is_connected = False
            self._jetstream_context = None

    async def publish(
        self,
        event: SecurityEvent,
        subject: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> str:
        """
        Publish security event to the bus.

        Automatically injects correlation ID from current context
        if not already present on the event.

        Args:
            event: Security event to publish
            subject: Optional custom subject (default: event_type)
            headers: Optional NATS headers for routing

        Returns:
            Event ID for tracking

        Raises:
            EventBusConnectionError: If not connected to NATS
            EventBusPublishError: If publish operation fails
        """
        if not self._is_connected or not self._client:
            raise EventBusConnectionError("Event bus not connected")

        event_subject = subject or f"{self.config.jetstream_stream}.{event.event_type.value}"

        event_with_correlation = event
        if not event.correlation_id:
            current_ctx = current_correlation()
            if current_ctx:
                event_with_correlation = event.with_correlation(current_ctx.correlation_id)

        event_data = json.dumps(event_with_correlation.to_dict()).encode("utf-8")

        nats_headers = headers or {}
        if event_with_correlation.correlation_id:
            nats_headers["X-Correlation-ID"] = event_with_correlation.correlation_id
        nats_headers["X-Event-ID"] = event_with_correlation.event_id
        nats_headers["X-Source-Agent"] = event_with_correlation.source

        try:
            if self.config.jetstream_enabled and self._jetstream_context:
                await self._jetstream_context.publish(
                    subject=event_subject,
                    payload=event_data,
                    headers=nats_headers,
                )
            else:
                await self._client.publish(
                    subject=event_subject,
                    payload=event_data,
                    headers=nats_headers,
                )

            return event_with_correlation.event_id

        except TimeoutError as e:
            raise EventBusPublishError(
                f"Publish timeout for event {event_with_correlation.event_id}"
            ) from e
        except Exception as e:
            raise EventBusPublishError(f"Failed to publish event: {e}") from e

    async def subscribe(
        self,
        event_types: list[str],
        handler: Callable[[SecurityEvent], Any],
        queue_group: Optional[str] = None,
        durable_name: Optional[str] = None,
    ) -> str:
        """
        Subscribe to security events with handler.

        Args:
            event_types: List of event type names to subscribe to
            handler: Async callback for event processing
            queue_group: Optional consumer group for load balancing
            durable_name: Optional durable consumer name for JetStream

        Returns:
            Subscription ID for management

        Raises:
            EventBusConnectionError: If not connected to NATS
            EventBusSubscribeError: If subscription fails
        """
        if not self._is_connected or not self._client:
            raise EventBusConnectionError("Event bus not connected")

        subscription_id = f"sub_{len(self._subscriptions)}"
        group = queue_group or self.config.queue_group

        async def message_handler(msg) -> None:
            try:
                event_data = json.loads(msg.data.decode("utf-8"))
                event = SecurityEvent.from_dict(event_data)

                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)

                if self.config.jetstream_enabled and hasattr(msg, "ack"):
                    await msg.ack()

            except json.JSONDecodeError as e:
                error_msg = f"Failed to decode event message: {e}"
                print(error_msg)
                if self.config.jetstream_enabled and hasattr(msg, "nak"):
                    await msg.nak()
            except Exception as e:
                error_msg = f"Error processing event: {e}"
                print(error_msg)
                if self.config.jetstream_enabled and hasattr(msg, "nak"):
                    await msg.nak()

        for event_type in event_types:
            subject = f"{self.config.jetstream_stream}.{event_type}"
            if self.config.jetstream_enabled and self._jetstream_context:
                consumer_name = durable_name or f"{group}_{event_type}"
                try:
                    consumer_info = await self._jetstream_context.consumer_info(
                        self.config.jetstream_stream, consumer_name
                    )
                except Exception:
                    await self._jetstream_context.add_consumer(
                        stream=self.config.jetstream_stream,
                        config={
                            "durable_name": consumer_name,
                            "ack_policy": "explicit",
                            "deliver_subject": f"{group}.{event_type}",
                            "filter_subject": subject,
                        },
                    )

                sub = await self._jetstream_context.subscribe(
                    subject=subject,
                    queue=group,
                    cb=message_handler,
                    durable=consumer_name,
                )
            else:
                sub = await self._client.subscribe(
                    subject=subject,
                    queue=group,
                    cb=message_handler,
                )
            self._subscriptions[f"{subscription_id}_{event_type}"] = sub

        return subscription_id

    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Remove subscription by ID.

        Args:
            subscription_id: Subscription identifier to remove
        """
        keys_to_remove = [
            key for key in self._subscriptions if key.startswith(subscription_id)
        ]
        for key in keys_to_remove:
            sub = self._subscriptions.pop(key)
            await sub.unsubscribe()

    async def request(
        self,
        event: SecurityEvent,
        timeout: Optional[float] = None,
    ) -> SecurityEvent:
        """
        Send request event and wait for response.

        Uses NATS request-response pattern for synchronous communication.

        Args:
            event: Request event
            timeout: Response timeout in seconds

        Returns:
            Response security event

        Raises:
            EventBusTimeoutError: If no response within timeout
            EventBusConnectionError: If not connected
        """
        if not self._is_connected or not self._client:
            raise EventBusConnectionError("Event bus not connected")

        timeout_value = timeout or self.config.request_timeout
        event_subject = f"{self.config.jetstream_stream}.{event.event_type.value}"
        event_data = json.dumps(event.to_dict()).encode("utf-8")

        try:
            msg = await self._client.request(
                subject=event_subject,
                payload=event_data,
                timeout=timeout_value,
            )
        except TimeoutError as e:
            raise EventBusTimeoutError(
                f"Request timeout for event {event.event_id}"
            ) from e

        response_data = json.loads(msg.data.decode("utf-8"))
        return SecurityEvent.from_dict(response_data)

    def register_error_handler(
        self,
        handler: Callable[[Exception], Any],
    ) -> None:
        """
        Register error handler for connection errors.

        Args:
            handler: Async or sync error handler callback
        """
        self._error_handlers.append(handler)

    async def _handle_error(self, error: Exception) -> None:
        """Handle NATS client errors."""
        for handler in self._error_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(error)
                else:
                    handler(error)
            except Exception as e:
                print(f"Error handler failed: {e}")

    def _handle_disconnect(self) -> None:
        """Handle NATS disconnection event."""
        self._is_connected = False

    def _handle_reconnect(self) -> None:
        """Handle NATS reconnection event."""
        self._is_connected = True
        self._reconnect_count = 0

    def _handle_closed(self) -> None:
        """Handle NATS connection closed event."""
        self._is_connected = False

    @property
    def is_connected(self) -> bool:
        """Check if event bus is connected."""
        return self._is_connected

    @property
    def connected_server(self) -> Optional[str]:
        """Get currently connected NATS server URL."""
        if self._client and self._client.is_connected:
            return self._client.connected_url.netloc
        return None

    async def __aenter__(self) -> "EventBus":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()
