"""
Circuit Breaker Pattern

Implementation of the circuit breaker pattern for LLM provider calls
to prevent cascading failures and enable graceful degradation.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, TypeVar

import structlog

from .exceptions import LLMProviderError
from .providers import LLMProvider, LLMResponse

logger = structlog.get_logger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:
    """
    Configuration for circuit breaker behavior.

    Attributes:
        failure_threshold: Number of consecutive failures before opening
        success_threshold: Number of successes in half-open to close
        timeout: Time in seconds before transitioning from open to half-open
        half_open_max_calls: Maximum calls allowed in half-open state
        monitor_window: Time window for tracking failures
        excluded_exceptions: Exceptions that don't count as failures
    """

    failure_threshold: int = 5
    success_threshold: int = 3
    timeout: float = 30.0
    half_open_max_calls: int = 3
    monitor_window: float = 60.0
    excluded_exceptions: set[type[Exception]] = field(default_factory=lambda: {
        LLMProviderError,
    })

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if self.success_threshold < 1:
            raise ValueError("success_threshold must be at least 1")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.half_open_max_calls < 1:
            raise ValueError("half_open_max_calls must be at least 1")
        if self.monitor_window <= 0:
            raise ValueError("monitor_window must be positive")


@dataclass
class CircuitMetrics:
    """
    Metrics for circuit breaker.

    Attributes:
        total_calls: Total calls made
        successful_calls: Successful calls
        failed_calls: Failed calls
        rejected_calls: Calls rejected due to open circuit
        last_failure_time: Timestamp of last failure
        last_success_time: Timestamp of last success
        consecutive_failures: Current consecutive failure count
        consecutive_successes: Current consecutive success count
        state_transitions: Number of state transitions
    """

    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    state_transitions: int = 0

    def record_call(self) -> None:
        """Record a call."""
        self.total_calls += 1

    def record_success(self) -> None:
        """Record a success."""
        self.successful_calls += 1
        self.last_success_time = time.monotonic()
        self.consecutive_successes += 1
        self.consecutive_failures = 0

    def record_failure(self) -> None:
        """Record a failure."""
        self.failed_calls += 1
        self.last_failure_time = time.monotonic()
        self.consecutive_failures += 1
        self.consecutive_successes = 0

    def record_rejection(self) -> None:
        """Record a rejection."""
        self.rejected_calls += 1

    def reset_consecutive(self) -> None:
        """Reset consecutive counters."""
        self.consecutive_failures = 0
        self.consecutive_successes = 0

    def record_transition(self) -> None:
        """Record state transition."""
        self.state_transitions += 1

    @property
    def success_rate(self) -> float:
        """Get success rate."""
        total = self.successful_calls + self.failed_calls
        if total == 0:
            return 0.0
        return self.successful_calls / total

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "rejected_calls": self.rejected_calls,
            "success_rate": self.success_rate,
            "consecutive_failures": self.consecutive_failures,
            "consecutive_successes": self.consecutive_successes,
            "state_transitions": self.state_transitions,
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
        }


class CircuitBreakerOpenError(LLMProviderError):
    """
    Exception raised when circuit breaker is open.

    Indicates that the circuit breaker has tripped due to
    consecutive failures and is temporarily rejecting calls.
    """

    def __init__(
        self,
        message: str = "Circuit breaker is open",
        provider: Optional[str] = None,
        time_until_retry: Optional[float] = None,
    ) -> None:
        super().__init__(message, provider)
        self.time_until_retry = time_until_retry

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary."""
        return {
            **super().to_dict(),
            "time_until_retry": self.time_until_retry,
        }


class CircuitBreaker:
    """
    Circuit breaker for LLM provider calls.

    Prevents cascading failures by temporarily blocking requests
    to a failing provider. Implements three states:

    - CLOSED: Normal operation, calls pass through
    - OPEN: Circuit tripped, calls are rejected immediately
    - HALF_OPEN: Testing recovery, limited calls allowed

    State transitions:
    - CLOSED -> OPEN: After failure_threshold consecutive failures
    - OPEN -> HALF_OPEN: After timeout seconds
    - HALF_OPEN -> CLOSED: After success_threshold consecutive successes
    - HALF_OPEN -> OPEN: On any failure

    Example usage:
        breaker = CircuitBreaker(provider, CircuitBreakerConfig())
        response = await breaker.complete(messages)
    """

    def __init__(
        self,
        provider: LLMProvider,
        config: Optional[CircuitBreakerConfig] = None,
        state_change_callback: Optional[Callable[[CircuitState, CircuitState], None]] = None,
    ) -> None:
        """
        Initialize circuit breaker.

        Args:
            provider: Wrapped LLM provider
            config: Circuit breaker configuration
            state_change_callback: Callback for state changes
        """
        self._provider = provider
        self._config = config or CircuitBreakerConfig()
        self._state_change_callback = state_change_callback

        self._state = CircuitState.CLOSED
        self._metrics = CircuitMetrics()
        self._open_until: Optional[float] = None
        self._half_open_calls: int = 0
        self._failure_times: list[float] = []

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        self._check_state_transition()
        return self._state

    @property
    def provider(self) -> LLMProvider:
        """Get wrapped provider."""
        return self._provider

    @property
    def config(self) -> CircuitBreakerConfig:
        """Get circuit breaker configuration."""
        return self._config

    @property
    def metrics(self) -> CircuitMetrics:
        """Get circuit metrics."""
        return self._metrics

    @property
    def provider_name(self) -> str:
        """Get provider name."""
        return self._provider.provider_name

    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self.state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """Check if circuit is open (rejecting calls)."""
        return self.state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        """Check if circuit is half-open (testing recovery)."""
        return self.state == CircuitState.HALF_OPEN

    def _check_state_transition(self) -> None:
        """Check if state should transition."""
        if self._state == CircuitState.OPEN and self._open_until:
            if time.monotonic() >= self._open_until:
                self._transition_to(CircuitState.HALF_OPEN)

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to new state."""
        if self._state == new_state:
            return

        old_state = self._state
        self._state = new_state
        self._metrics.record_transition()

        logger.info(
            "Circuit breaker state transition",
            provider=self.provider_name,
            old_state=old_state.value,
            new_state=new_state.value,
        )

        if self._state_change_callback:
            self._state_change_callback(old_state, new_state)

    def _should_count_failure(self, exception: Exception) -> bool:
        """Check if exception should count as failure."""
        for excluded in self._config.excluded_exceptions:
            if isinstance(exception, excluded):
                return False
        return True

    def _record_failure(self) -> None:
        """Record a failure and potentially open circuit."""
        self._metrics.record_failure()
        self._failure_times.append(time.monotonic())

        if self._state == CircuitState.HALF_OPEN:
            self._open_until = time.monotonic() + self._config.timeout
            self._transition_to(CircuitState.OPEN)
            return

        if self._state == CircuitState.CLOSED:
            if self._metrics.consecutive_failures >= self._config.failure_threshold:
                self._open_until = time.monotonic() + self._config.timeout
                self._transition_to(CircuitState.OPEN)

    def _record_success(self) -> None:
        """Record a success and potentially close circuit."""
        self._metrics.record_success()

        if self._state == CircuitState.HALF_OPEN:
            self._half_open_calls += 1
            if self._metrics.consecutive_successes >= self._config.success_threshold:
                self._transition_to(CircuitState.CLOSED)
                self._half_open_calls = 0

    async def complete(self, messages: Any, **kwargs: Any) -> LLMResponse:
        """
        Execute completion with circuit breaker protection.

        Args:
            messages: Conversation messages
            **kwargs: Provider-specific parameters

        Returns:
            LLMResponse with completion

        Raises:
            CircuitBreakerOpenError: When circuit is open
        """
        self._metrics.record_call()

        if self._state == CircuitState.OPEN:
            self._metrics.record_rejection()
            time_until_retry = 0.0
            if self._open_until:
                time_until_retry = max(0, self._open_until - time.monotonic())

            error = CircuitBreakerOpenError(
                f"Circuit breaker open for {self.provider_name}",
                provider=self.provider_name,
                time_until_retry=time_until_retry,
            )
            logger.warning(
                "Circuit breaker rejecting call",
                provider=self.provider_name,
                time_until_retry=time_until_retry,
            )
            raise error

        if self._state == CircuitState.HALF_OPEN:
            if self._half_open_calls >= self._config.half_open_max_calls:
                self._metrics.record_rejection()
                error = CircuitBreakerOpenError(
                    f"Circuit breaker half-open max calls reached",
                    provider=self.provider_name,
                )
                logger.warning(
                    "Circuit breaker half-open limit reached",
                    provider=self.provider_name,
                )
                raise error

        try:
            response = await self._provider.complete(messages, **kwargs)
            self._record_success()
            return response

        except Exception as error:
            if self._should_count_failure(error):
                self._record_failure()
            raise

    async def complete_stream(self, messages: Any, **kwargs: Any) -> Any:
        """
        Execute streaming completion with circuit breaker protection.

        Args:
            messages: Conversation messages
            **kwargs: Provider-specific parameters

        Yields:
            Response content chunks

        Raises:
            CircuitBreakerOpenError: When circuit is open
        """
        self._metrics.record_call()

        if self._state == CircuitState.OPEN:
            self._metrics.record_rejection()
            time_until_retry = 0.0
            if self._open_until:
                time_until_retry = max(0, self._open_until - time.monotonic())

            error = CircuitBreakerOpenError(
                f"Circuit breaker open for {self.provider_name}",
                provider=self.provider_name,
                time_until_retry=time_until_retry,
            )
            logger.warning(
                "Circuit breaker rejecting streaming call",
                provider=self.provider_name,
                time_until_retry=time_until_retry,
            )
            raise error

        if self._state == CircuitState.HALF_OPEN:
            if self._half_open_calls >= self._config.half_open_max_calls:
                self._metrics.record_rejection()
                error = CircuitBreakerOpenError(
                    f"Circuit breaker half-open max calls reached",
                    provider=self.provider_name,
                )
                logger.warning(
                    "Circuit breaker half-open limit reached for streaming",
                    provider=self.provider_name,
                )
                raise error

        try:
            async for chunk in self._provider.complete_stream(messages, **kwargs):
                yield chunk
            self._record_success()

        except Exception as error:
            if self._should_count_failure(error):
                self._record_failure()
            raise

    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        self._transition_to(CircuitState.CLOSED)
        self._metrics.reset_consecutive()
        self._open_until = None
        self._half_open_calls = 0
        self._failure_times.clear()
        logger.info("Circuit breaker reset", provider=self.provider_name)

    def force_open(self) -> None:
        """Force circuit to open state."""
        self._open_until = time.monotonic() + self._config.timeout
        self._transition_to(CircuitState.OPEN)
        logger.info("Circuit breaker forced open", provider=self.provider_name)

    def force_close(self) -> None:
        """Force circuit to closed state."""
        self._transition_to(CircuitState.CLOSED)
        self._metrics.reset_consecutive()
        self._open_until = None
        self._half_open_calls = 0
        self._failure_times.clear()
        logger.info("Circuit breaker forced closed", provider=self.provider_name)

    def get_status(self) -> dict[str, Any]:
        """Get current circuit breaker status."""
        time_until_retry = None
        if self._state == CircuitState.OPEN and self._open_until:
            time_until_retry = max(0, self._open_until - time.monotonic())

        return {
            "provider": self.provider_name,
            "state": self._state.value,
            "is_closed": self.is_closed,
            "is_open": self.is_open,
            "is_half_open": self.is_half_open,
            "time_until_retry": time_until_retry,
            "metrics": self._metrics.to_dict(),
        }

    async def close(self) -> None:
        """Close underlying provider."""
        await self._provider.close()

    async def __aenter__(self) -> "CircuitBreaker":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()


class CircuitBreakerRegistry:
    """
    Registry for managing multiple circuit breakers.

    Provides centralized management of circuit breakers for
    multiple providers with automatic creation and lookup.
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None) -> None:
        """
        Initialize circuit breaker registry.

        Args:
            config: Default configuration for new circuit breakers
        """
        self._config = config or CircuitBreakerConfig()
        self._breakers: dict[str, CircuitBreaker] = {}

    def get_or_create(self, provider: LLMProvider) -> CircuitBreaker:
        """
        Get or create circuit breaker for provider.

        Args:
            provider: LLM provider

        Returns:
            Circuit breaker instance
        """
        provider_name = provider.provider_name
        if provider_name not in self._breakers:
            self._breakers[provider_name] = CircuitBreaker(provider, self._config)
        return self._breakers[provider_name]

    def get(self, provider_name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by provider name."""
        return self._breakers.get(provider_name)

    def remove(self, provider_name: str) -> None:
        """Remove circuit breaker."""
        if provider_name in self._breakers:
            del self._breakers[provider_name]

    def list_all(self) -> list[str]:
        """List all registered circuit breakers."""
        return list(self._breakers.keys())

    def get_all_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all circuit breakers."""
        return {name: breaker.get_status() for name, breaker in self._breakers.items()}

    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            breaker.reset()

    def close_all(self) -> None:
        """Close all circuit breakers."""
        for breaker in self._breakers.values():
            asyncio.create_task(breaker.close())
