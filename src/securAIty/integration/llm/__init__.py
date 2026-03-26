"""
LLM Provider Package

Multi-provider LLM abstraction layer for securAIty.
Supports Ollama, OpenRouter, Gemini, and ChatGPT providers
with unified interface, streaming, and token tracking.

Example usage:
    from securAIty.integration.llm import LLMClient, LLMProviderFactory

    Create provider directly:
    provider = LLMProviderFactory.create("ollama", model="qwen2.5:72b")
    response = await provider.complete([LLMMessage(role="user", content="Hello")])

    Use high-level client with automatic retry:
    async with LLMClient() as client:
        response = await client.complete(prompt="Hello, world!")
        print(response.content)
        print(client.retry_status)

    Create provider with unlimited retry:
    provider = LLMProviderFactory.create_with_retry("ollama", max_retries=-1)
    response = await provider.complete(messages)

    Use environment-based configuration:
    SECURAITY_LLM_PROVIDER=ollama
    SECURAITY_LLM_MODEL=qwen2.5:72b
    SECURAITY_LLM_MAX_RETRIES=-1
    client = LLMClient()
"""

from .circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitBreakerRegistry,
    CircuitMetrics,
    CircuitState,
)
from .client import ConversationHistory, ConversationTurn, LLMClient, LLMClientConfig, MultiProviderClient, TokenUsage
from .config import (
    ChatGPTConfig,
    GeminiConfig,
    LLMProviderConfig,
    OllamaConfig,
    OpenRouterConfig,
)
from .exceptions import (
    ChatGPTProviderError,
    CircuitBreakerOpenError,
    GeminiProviderError,
    LLMProviderAuthenticationError,
    LLMProviderConnectionError,
    LLMProviderError,
    LLMProviderNotAvailableError,
    LLMProviderRateLimitError,
    LLMProviderResponseError,
    LLMProviderTimeoutError,
    LLMProviderValidationError,
    MaxRetriesExceededError,
    NonRetryableError,
    OllamaProviderError,
    OpenRouterProviderError,
    RetryableError,
)
from .factory import (
    LLMProviderFactory,
    create_provider,
    create_provider_from_env,
    create_provider_with_circuit_breaker,
    create_provider_with_retry,
)
from .providers import (
    ChatGPTProvider,
    GeminiProvider,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    OllamaProvider,
    OpenRouterProvider,
)
from .retry import (
    MaxRetriesExceededError,
    NonRetryableError,
    PersistentRetryExecutor,
    RetryConfig,
    RetryMetrics,
    RetryableError,
    with_retry,
)

__all__ = [
    "LLMProvider",
    "LLMMessage",
    "LLMResponse",
    "LLMProviderConfig",
    "OllamaConfig",
    "OpenRouterConfig",
    "GeminiConfig",
    "ChatGPTConfig",
    "OllamaProvider",
    "OpenRouterProvider",
    "GeminiProvider",
    "ChatGPTProvider",
    "LLMProviderFactory",
    "create_provider",
    "create_provider_from_env",
    "create_provider_with_retry",
    "create_provider_with_circuit_breaker",
    "LLMClient",
    "LLMClientConfig",
    "MultiProviderClient",
    "ConversationHistory",
    "ConversationTurn",
    "TokenUsage",
    "LLMProviderError",
    "LLMProviderAuthenticationError",
    "LLMProviderRateLimitError",
    "LLMProviderTimeoutError",
    "LLMProviderConnectionError",
    "LLMProviderValidationError",
    "LLMProviderNotAvailableError",
    "LLMProviderResponseError",
    "OllamaProviderError",
    "OpenRouterProviderError",
    "GeminiProviderError",
    "ChatGPTProviderError",
    "RetryableError",
    "NonRetryableError",
    "MaxRetriesExceededError",
    "CircuitBreakerOpenError",
    "PersistentRetryExecutor",
    "RetryConfig",
    "RetryMetrics",
    "with_retry",
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerRegistry",
    "CircuitMetrics",
    "CircuitState",
]
