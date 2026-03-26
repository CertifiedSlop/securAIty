"""
Persistent Retry Executor

Retry mechanism for LLM provider operations with exponential backoff,
jitter, and comprehensive error handling. Supports unlimited retries
for critical subagent operations.
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, TypeVar

import structlog

from .exceptions import (
    LLMProviderAuthenticationError,
    LLMProviderError,
    LLMProviderNotAvailableError,
)
from .providers import LLMProvider, LLMResponse

logger = structlog.get_logger(__name__)

T = TypeVar("T")


@dataclass
class RetryConfig:
    """
    Configuration for retry behavior.

    Attributes:
        max_retries: Maximum retry attempts (-1 for unlimited)
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay cap in seconds
        exponential_base: Exponential backoff multiplier
        jitter: Add randomness to prevent thundering herd
        timeout_multiplier: Increase timeout on each retry
        retryable_status_codes: HTTP status codes that trigger retry
        retryable_exceptions: Exception types that trigger retry
    """

    max_retries: int = -1
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    timeout_multiplier: float = 1.5
    retryable_status_codes: set[int] = field(default_factory=lambda: {429, 500, 502, 503, 504})
    retryable_exceptions: set[type[Exception]] = field(default_factory=lambda: {
        ConnectionError,
        TimeoutError,
        OSError,
    })

    def get_delay(self, attempt: int) -> float:
        """
        Calculate delay for given attempt with exponential backoff and jitter.

        Args:
            attempt: Current attempt number (0-indexed)

        Returns:
            Delay in seconds
        """
        delay = min(self.base_delay * (self.exponential_base**attempt), self.max_delay)

        if self.jitter:
            jitter_range = min(delay * 0.2, 1.0)
            delay += random.uniform(-jitter_range, jitter_range)

        return max(0.1, delay)

    def get_timeout(self, base_timeout: float, attempt: int) -> float:
        """
        Calculate timeout for given attempt with progressive increase.

        Args:
            base_timeout: Base timeout in seconds
            attempt: Current attempt number

        Returns:
            Timeout in seconds
        """
        return base_timeout * (self.timeout_multiplier**attempt)


@dataclass
class RetryMetrics:
    """
    Metrics for retry operations.

    Attributes:
        total_attempts: Total number of attempts made
        successful_attempts: Number of successful attempts
        failed_attempts: Number of failed attempts
        total_retry_time: Total time spent retrying in seconds
        last_error: Last error encountered
        last_error_type: Type of last error
    """

    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    total_retry_time: float = 0.0
    last_error: Optional[str] = None
    last_error_type: Optional[str] = None

    def record_attempt(self, success: bool, error: Optional[Exception] = None) -> None:
        """Record an attempt."""
        self.total_attempts += 1
        if success:
            self.successful_attempts += 1
        else:
            self.failed_attempts += 1
            if error:
                self.last_error = str(error)
                self.last_error_type = type(error).__name__

    def record_time(self, duration: float) -> None:
        """Record time spent."""
        self.total_retry_time += duration

    @property
    def success_rate(self) -> float:
        """Get success rate."""
        if self.total_attempts == 0:
            return 0.0
        return self.successful_attempts / self.total_attempts

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_attempts": self.total_attempts,
            "successful_attempts": self.successful_attempts,
            "failed_attempts": self.failed_attempts,
            "success_rate": self.success_rate,
            "total_retry_time": self.total_retry_time,
            "last_error": self.last_error,
            "last_error_type": self.last_error_type,
        }


class RetryableError(LLMProviderError):
    """
    Exception indicating a retryable error.

    Used to explicitly mark an error as retryable.
    """

    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        original_exception: Optional[Exception] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message, provider, original_exception)
        self.retry_after = retry_after


class NonRetryableError(LLMProviderError):
    """
    Exception indicating a non-retryable error.

    Used to explicitly mark an error as non-retryable.
    Authentication errors and configuration errors should use this.
    """

    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, provider, original_exception)


class MaxRetriesExceededError(LLMProviderError):
    """
    Exception raised when maximum retries are exceeded.

    Only raised when max_retries is explicitly set and exceeded.
    """

    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        total_attempts: int = 0,
        total_time: float = 0.0,
        last_error: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, provider, last_error)
        self.total_attempts = total_attempts
        self.total_time = total_time
        self.last_error = last_error

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary."""
        return {
            **super().to_dict(),
            "total_attempts": self.total_attempts,
            "total_time": self.total_time,
            "last_error": str(self.last_error) if self.last_error else None,
        }


class PersistentRetryExecutor:
    """
    Persistent retry wrapper for LLM providers.

    Wraps any LLM provider and adds persistent retry logic with
    exponential backoff, jitter, and comprehensive error classification.

    Key features:
    - Unlimited retries by default (max_retries=-1)
    - Exponential backoff with jitter
    - Progressive timeout increase
    - Smart error classification (retryable vs non-retryable)
    - Comprehensive metrics and logging
    - Event emission for retry attempts

    Example usage:
        provider = OllamaProvider(config)
        retry_provider = PersistentRetryExecutor(
            provider=provider,
            config=RetryConfig(max_retries=-1)
        )
        response = await retry_provider.complete(messages)
    """

    def __init__(
        self,
        provider: LLMProvider,
        config: Optional[RetryConfig] = None,
        event_callback: Optional[Callable[[str, dict[str, Any]], None]] = None,
    ) -> None:
        """
        Initialize persistent retry executor.

        Args:
            provider: Wrapped LLM provider
            config: Retry configuration
            event_callback: Optional callback for retry events
        """
        self._provider = provider
        self._config = config or RetryConfig()
        self._event_callback = event_callback
        self._metrics = RetryMetrics()
        self._is_wrapped = True

    @property
    def provider(self) -> LLMProvider:
        """Get wrapped provider."""
        return self._provider

    @property
    def config(self) -> RetryConfig:
        """Get retry configuration."""
        return self._config

    @property
    def metrics(self) -> RetryMetrics:
        """Get retry metrics."""
        return self._metrics

    @property
    def provider_name(self) -> str:
        """Get provider name."""
        return self._provider.provider_name

    @property
    def config_object(self) -> Any:
        """Get provider config."""
        return self._provider.config

    def _emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit retry event."""
        if self._event_callback:
            self._event_callback(event_type, data)

        log_data = {
            "event": event_type,
            "provider": self.provider_name,
            **data,
        }

        if event_type.endswith(".error") or event_type.endswith(".exhausted"):
            logger.error("Retry event", **log_data)
        elif event_type.endswith(".attempt"):
            logger.info("Retry attempt", **log_data)
        else:
            logger.info("Retry event", **log_data)

    def _is_retryable_error(self, error: Exception) -> bool:
        """
        Determine if error is retryable.

        Non-retryable errors:
        - Authentication errors (401, invalid credentials)
        - Provider not available (configuration error)
        - Explicit NonRetryableError

        Retryable errors:
        - Rate limiting (429)
        - Server errors (5xx)
        - Connection errors
        - Timeout errors
        - Invalid responses (malformed JSON, empty responses)
        """
        if isinstance(error, NonRetryableError):
            return False

        if isinstance(error, LLMProviderAuthenticationError):
            return False

        if isinstance(error, LLMProviderNotAvailableError):
            return False

        if isinstance(error, RetryableError):
            return True

        if isinstance(error, LLMProviderError):
            status_code = getattr(error, "status_code", None)
            if status_code and status_code in self._config.retryable_status_codes:
                return True
            if status_code and status_code not in {400, 401, 403, 404}:
                return True

        for exc_type in self._config.retryable_exceptions:
            if isinstance(error, exc_type):
                return True

        error_str = str(error).lower()
        if any(phrase in error_str for phrase in ["timeout", "connection", "rate limit", "temporary"]):
            return True

        return False

    def _get_retry_after(self, error: Exception) -> Optional[float]:
        """Extract retry-after from error."""
        retry_after = getattr(error, "retry_after", None)
        if retry_after:
            return retry_after

        error_str = str(error).lower()
        if "retry after" in error_str:
            try:
                for part in error_str.split():
                    if part.isdigit():
                        return float(part)
            except (ValueError, IndexError):
                pass

        return None

    async def complete(
        self,
        messages: Any,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Execute completion with persistent retry.

        Args:
            messages: Conversation messages
            **kwargs: Provider-specific parameters

        Returns:
            LLMResponse with completion

        Raises:
            MaxRetriesExceededError: When max_retries is exceeded
            NonRetryableError: When non-retryable error occurs
        """
        start_time = time.monotonic()
        attempt = 0
        last_error: Optional[Exception] = None

        base_timeout = getattr(self._provider.config, "timeout", 60.0)

        while True:
            is_unlimited = self._config.max_retries < 0
            should_continue = is_unlimited or attempt <= self._config.max_retries

            if not should_continue:
                total_time = time.monotonic() - start_time
                error = MaxRetriesExceededError(
                    f"Max retries ({self._config.max_retries}) exceeded for {self.provider_name}",
                    provider=self.provider_name,
                    total_attempts=attempt,
                    total_time=total_time,
                    last_error=last_error,
                )
                self._emit_event("llm.retry.exhausted", {
                    "total_attempts": attempt,
                    "total_time": total_time,
                    "error": str(error),
                })
                raise error

            try:
                current_timeout = self._config.get_timeout(base_timeout, attempt)
                original_timeout = getattr(self._provider.config, "timeout", None)
                if original_timeout:
                    self._provider.config.timeout = current_timeout

                response = await self._provider.complete(messages, **kwargs)

                if original_timeout:
                    self._provider.config.timeout = original_timeout

                total_time = time.monotonic() - start_time
                self._metrics.record_attempt(True)
                self._metrics.record_time(total_time)

                response_metadata = getattr(response, "metadata", {})
                if hasattr(response, "raw_response"):
                    if not isinstance(response.raw_response, dict):
                        response.raw_response = {}
                    response.raw_response["retry_count"] = attempt
                    response.raw_response["retry_time"] = total_time

                if attempt > 0:
                    self._emit_event("llm.retry.success", {
                        "attempts": attempt,
                        "total_time": total_time,
                    })

                return response

            except Exception as error:
                total_time = time.monotonic() - start_time
                last_error = error

                if original_timeout:
                    self._provider.config.timeout = original_timeout

                if not self._is_retryable_error(error):
                    self._metrics.record_attempt(False, error)
                    self._emit_event("llm.retry.non_retryable_error", {
                        "attempt": attempt,
                        "error_type": type(error).__name__,
                        "error": str(error),
                    })
                    raise

                self._metrics.record_attempt(False, error)
                self._metrics.record_time(total_time)

                retry_after = self._get_retry_after(error)
                delay = retry_after if retry_after else self._config.get_delay(attempt)

                self._emit_event("llm.retry.attempt", {
                    "attempt": attempt,
                    "error_type": type(error).__name__,
                    "error": str(error),
                    "delay": delay,
                    "total_time": total_time,
                })

                attempt += 1
                await asyncio.sleep(delay)

    async def complete_stream(self, messages: Any, **kwargs: Any) -> Any:
        """
        Execute streaming completion with persistent retry.

        Args:
            messages: Conversation messages
            **kwargs: Provider-specific parameters

        Yields:
            Response content chunks

        Raises:
            MaxRetriesExceededError: When max_retries is exceeded
            NonRetryableError: When non-retryable error occurs
        """
        start_time = time.monotonic()
        attempt = 0
        last_error: Optional[Exception] = None

        base_timeout = getattr(self._provider.config, "timeout", 60.0)

        while True:
            is_unlimited = self._config.max_retries < 0
            should_continue = is_unlimited or attempt <= self._config.max_retries

            if not should_continue:
                total_time = time.monotonic() - start_time
                error = MaxRetriesExceededError(
                    f"Max retries ({self._config.max_retries}) exceeded for streaming",
                    provider=self.provider_name,
                    total_attempts=attempt,
                    total_time=total_time,
                    last_error=last_error,
                )
                self._emit_event("llm.retry.exhausted", {
                    "total_attempts": attempt,
                    "total_time": total_time,
                    "error": str(error),
                })
                raise error

            try:
                current_timeout = self._config.get_timeout(base_timeout, attempt)
                original_timeout = getattr(self._provider.config, "timeout", None)
                if original_timeout:
                    self._provider.config.timeout = current_timeout

                async for chunk in self._provider.complete_stream(messages, **kwargs):
                    yield chunk

                if original_timeout:
                    self._provider.config.timeout = original_timeout

                total_time = time.monotonic() - start_time
                self._metrics.record_attempt(True)
                self._metrics.record_time(total_time)

                if attempt > 0:
                    self._emit_event("llm.retry.success", {
                        "attempts": attempt,
                        "total_time": total_time,
                    })

                return

            except Exception as error:
                total_time = time.monotonic() - start_time
                last_error = error

                if original_timeout:
                    self._provider.config.timeout = original_timeout

                if not self._is_retryable_error(error):
                    self._metrics.record_attempt(False, error)
                    self._emit_event("llm.retry.non_retryable_error", {
                        "attempt": attempt,
                        "error_type": type(error).__name__,
                        "error": str(error),
                    })
                    raise

                self._metrics.record_attempt(False, error)
                self._metrics.record_time(total_time)

                retry_after = self._get_retry_after(error)
                delay = retry_after if retry_after else self._config.get_delay(attempt)

                self._emit_event("llm.retry.attempt", {
                    "attempt": attempt,
                    "error_type": type(error).__name__,
                    "error": str(error),
                    "delay": delay,
                    "total_time": total_time,
                })

                attempt += 1
                await asyncio.sleep(delay)

    async def close(self) -> None:
        """Close underlying provider."""
        await self._provider.close()

    async def __aenter__(self) -> "PersistentRetryExecutor":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    def get_retry_status(self) -> dict[str, Any]:
        """Get current retry status."""
        return {
            "provider": self.provider_name,
            "is_wrapped": self._is_wrapped,
            "max_retries": self._config.max_retries,
            "is_unlimited": self._config.max_retries < 0,
            "metrics": self._metrics.to_dict(),
        }


def with_retry(
    provider: LLMProvider,
    max_retries: int = -1,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
) -> PersistentRetryExecutor:
    """
    Convenience function to wrap provider with retry.

    Args:
        provider: LLM provider to wrap
        max_retries: Maximum retries (-1 for unlimited)
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Exponential backoff base
        jitter: Enable jitter

    Returns:
        Wrapped provider with retry
    """
    config = RetryConfig(
        max_retries=max_retries,
        base_delay=base_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        jitter=jitter,
    )
    return PersistentRetryExecutor(provider, config)
