"""
LLM Provider Exceptions

Custom exceptions for LLM provider operations with provider-specific
error handling and retry logic support.
"""

from typing import Any, Optional


class LLMProviderError(Exception):
    """Base exception for LLM provider errors."""

    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        self.message = message
        self.provider = provider
        self.original_exception = original_exception
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for logging."""
        return {
            "type": self.__class__.__name__,
            "message": self.message,
            "provider": self.provider,
            "original_exception": str(self.original_exception) if self.original_exception else None,
        }


class LLMProviderAuthenticationError(LLMProviderError):
    """Authentication failed for LLM provider."""

    def __init__(
        self,
        message: str = "Authentication failed",
        provider: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, provider, original_exception)


class LLMProviderRateLimitError(LLMProviderError):
    """Rate limit exceeded for LLM provider."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        provider: Optional[str] = None,
        retry_after: Optional[float] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, provider, original_exception)
        self.retry_after = retry_after


class LLMProviderTimeoutError(LLMProviderError):
    """Request timeout for LLM provider."""

    def __init__(
        self,
        message: str = "Request timed out",
        provider: Optional[str] = None,
        timeout: Optional[float] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, provider, original_exception)
        self.timeout = timeout


class LLMProviderConnectionError(LLMProviderError):
    """Connection failed for LLM provider."""

    def __init__(
        self,
        message: str = "Connection failed",
        provider: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, provider, original_exception)


class LLMProviderValidationError(LLMProviderError):
    """Validation failed for LLM provider request or response."""

    def __init__(
        self,
        message: str = "Validation failed",
        provider: Optional[str] = None,
        field: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, provider, original_exception)
        self.field = field


class LLMProviderNotAvailableError(LLMProviderError):
    """LLM provider is not available or not configured."""

    def __init__(
        self,
        message: str = "Provider not available",
        provider: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, provider, original_exception)


class LLMProviderResponseError(LLMProviderError):
    """Invalid or unexpected response from LLM provider."""

    def __init__(
        self,
        message: str = "Invalid response from provider",
        provider: Optional[str] = None,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, provider, original_exception)
        self.status_code = status_code
        self.response_body = response_body


class OllamaProviderError(LLMProviderError):
    """Ollama-specific provider error."""

    def __init__(
        self,
        message: str,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, "ollama", original_exception)


class OpenRouterProviderError(LLMProviderError):
    """OpenRouter-specific provider error."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, "openrouter", original_exception)
        self.status_code = status_code


class GeminiProviderError(LLMProviderError):
    """Gemini-specific provider error."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, "gemini", original_exception)
        self.status_code = status_code


class ChatGPTProviderError(LLMProviderError):
    """ChatGPT/OpenAI-specific provider error."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__(message, "chatgpt", original_exception)
        self.status_code = status_code


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
