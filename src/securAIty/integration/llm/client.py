"""
Unified LLM Client

High-level client for LLM operations with provider abstraction,
conversation management, and token usage tracking.
"""

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Callable, Optional

from .circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from .config import LLMProviderConfig
from .factory import LLMProviderFactory
from .providers import LLMMessage, LLMProvider, LLMResponse
from .retry import PersistentRetryExecutor, RetryConfig


@dataclass
class LLMClientConfig:
    """
    Configuration for LLM client.

    Attributes:
        provider_config: Provider configuration
        retry_config: Retry configuration
        circuit_breaker_config: Circuit breaker configuration
        enable_retry: Enable retry wrapper
        enable_circuit_breaker: Enable circuit breaker
        track_usage: Enable token usage tracking
        system_message: Optional system message
    """

    provider_config: Optional[LLMProviderConfig] = None
    retry_config: Optional[RetryConfig] = None
    circuit_breaker_config: Optional[CircuitBreakerConfig] = None
    enable_retry: bool = True
    enable_circuit_breaker: bool = False
    track_usage: bool = True
    system_message: Optional[str] = None

    @classmethod
    def from_env(cls) -> "LLMClientConfig":
        """Create config from environment."""
        provider_config = LLMProviderConfig.from_env()
        retry_config = RetryConfig(
            max_retries=int(os.environ.get("SECURAITY_LLM_MAX_RETRIES", "-1")),
            base_delay=float(os.environ.get("SECURAITY_LLM_RETRY_BASE_DELAY", "1.0")),
            max_delay=float(os.environ.get("SECURAITY_LLM_RETRY_MAX_DELAY", "60.0")),
            jitter=os.environ.get("SECURAITY_LLM_RETRY_JITTER", "true").lower() == "true",
        )
        circuit_breaker_config = CircuitBreakerConfig(
            failure_threshold=int(os.environ.get("SECURAITY_LLM_CB_FAILURE_THRESHOLD", "5")),
            timeout=float(os.environ.get("SECURAITY_LLM_CB_TIMEOUT", "30.0")),
        )
        enable_retry = os.environ.get("SECURAITY_LLM_ENABLE_RETRY", "true").lower() == "true"
        enable_circuit_breaker = os.environ.get("SECURAITY_LLM_ENABLE_CB", "false").lower() == "true"

        return cls(
            provider_config=provider_config,
            retry_config=retry_config,
            circuit_breaker_config=circuit_breaker_config,
            enable_retry=enable_retry,
            enable_circuit_breaker=enable_circuit_breaker,
        )


@dataclass
class TokenUsage:
    """
    Token usage statistics.

    Attributes:
        prompt_tokens: Tokens in prompt
        completion_tokens: Tokens in completion
        total_tokens: Total tokens used
        request_count: Number of requests made
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    request_count: int = 0

    def add(self, response: LLMResponse) -> None:
        """Add token usage from response."""
        self.prompt_tokens += response.prompt_tokens
        self.completion_tokens += response.completion_tokens
        self.total_tokens += response.total_tokens
        self.request_count += 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "request_count": self.request_count,
        }


@dataclass
class ConversationTurn:
    """
    Single turn in a conversation.

    Attributes:
        role: Message role
        content: Message content
        timestamp: When message was created
        tokens: Token count for message
    """

    role: str
    content: str
    timestamp: float = field(default_factory=time.time)
    tokens: int = 0


@dataclass
class ConversationHistory:
    """
    Conversation history manager.

    Attributes:
        system_message: Optional system message
        turns: Conversation turns
        max_turns: Maximum turns to keep
    """

    system_message: Optional[str] = None
    turns: list[ConversationTurn] = field(default_factory=list)
    max_turns: int = 100

    def add_message(self, role: str, content: str, tokens: int = 0) -> None:
        """Add message to history."""
        self.turns.append(ConversationTurn(role=role, content=content, tokens=tokens))
        if len(self.turns) > self.max_turns:
            self.turns = self.turns[-self.max_turns:]

    def to_messages(self) -> list[LLMMessage]:
        """Convert to LLMMessage list."""
        messages = []
        if self.system_message:
            messages.append(LLMMessage(role="system", content=self.system_message))
        for turn in self.turns:
            messages.append(LLMMessage(role=turn.role, content=turn.content))
        return messages

    def clear(self) -> None:
        """Clear conversation history."""
        self.turns = []

    def get_turn_count(self) -> int:
        """Get number of turns."""
        return len(self.turns)


class LLMClient:
    """
    Unified LLM client for multi-provider support.

    Provides a consistent interface for all LLM operations
    with built-in conversation management and usage tracking.

    Features:
    - Automatic retry with exponential backoff (enabled by default)
    - Optional circuit breaker for failure isolation
    - Conversation history management
    - Token usage tracking

    Example usage:
        async with LLMClient() as client:
            response = await client.complete(prompt="Hello!")
            print(response.content)
    """

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        config: Optional[LLMProviderConfig] = None,
        client_config: Optional[LLMClientConfig] = None,
        system_message: Optional[str] = None,
        track_usage: bool = True,
    ) -> None:
        """
        Initialize LLM client.

        Args:
            provider: Pre-configured provider instance
            config: Provider configuration (deprecated, use client_config)
            client_config: Full client configuration
            system_message: Optional system message
            track_usage: Enable token usage tracking
        """
        if client_config is not None:
            self._client_config = client_config
            provider_config = client_config.provider_config or config
        else:
            if config is None:
                config = LLMProviderConfig.from_env()
            self._client_config = LLMClientConfig(provider_config=config)
            provider_config = config

        if provider is None:
            if provider_config is None:
                provider_config = LLMProviderConfig.from_env()
            self._raw_provider = LLMProviderFactory.create(provider_config.provider, provider_config)
        else:
            self._raw_provider = provider

        self._config = self._raw_provider.config

        wrapped_provider = self._raw_provider

        if self._client_config.enable_circuit_breaker and self._client_config.circuit_breaker_config:
            wrapped_provider = CircuitBreaker(
                wrapped_provider,
                self._client_config.circuit_breaker_config,
            )

        if self._client_config.enable_retry and self._client_config.retry_config:
            wrapped_provider = PersistentRetryExecutor(
                wrapped_provider,
                self._client_config.retry_config,
            )

        self._provider = wrapped_provider
        self._conversation = ConversationHistory(system_message=system_message)
        self._track_usage = track_usage
        self._usage = TokenUsage()
        self._is_connected = False

    @property
    def provider_name(self) -> str:
        """Get current provider name."""
        return self._provider.provider_name

    @property
    def model(self) -> str:
        """Get current model name."""
        return self._config.model

    @property
    def usage(self) -> TokenUsage:
        """Get token usage statistics."""
        return self._usage

    @property
    def conversation_history(self) -> ConversationHistory:
        """Get conversation history."""
        return self._conversation

    @property
    def retry_status(self) -> Optional[dict[str, Any]]:
        """Get retry status if retry is enabled."""
        if isinstance(self._provider, PersistentRetryExecutor):
            return self._provider.get_retry_status()
        return None

    @property
    def circuit_breaker_status(self) -> Optional[dict[str, Any]]:
        """Get circuit breaker status if enabled."""
        if isinstance(self._provider, CircuitBreaker):
            return self._provider.get_status()
        return None

    @property
    def raw_provider(self) -> LLMProvider:
        """Get underlying raw provider."""
        return self._raw_provider

    @property
    def is_retry_enabled(self) -> bool:
        """Check if retry is enabled."""
        return isinstance(self._provider, PersistentRetryExecutor)

    @property
    def is_circuit_breaker_enabled(self) -> bool:
        """Check if circuit breaker is enabled."""
        if isinstance(self._provider, CircuitBreaker):
            return True
        if isinstance(self._provider, PersistentRetryExecutor):
            return isinstance(self._provider.provider, CircuitBreaker)
        return False

    async def connect(self) -> None:
        """Connect to LLM provider."""
        self._is_connected = True

    async def disconnect(self) -> None:
        """Disconnect from LLM provider."""
        await self._provider.close()
        self._is_connected = False

    async def complete(
        self,
        messages: Optional[list[LLMMessage]] = None,
        prompt: Optional[str] = None,
        system_message: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Get completion from LLM.

        Args:
            messages: Optional list of messages
            prompt: Optional single prompt
            system_message: Optional system message override
            max_tokens: Optional max tokens override
            temperature: Optional temperature override
            **kwargs: Provider-specific parameters

        Returns:
            LLMResponse with completion

        Raises:
            RuntimeError: If not connected
        """
        if not self._is_connected:
            raise RuntimeError("LLM client not connected. Call connect() first.")

        request_messages = self._build_messages(messages, prompt, system_message)

        completion_kwargs = {}
        if max_tokens is not None:
            completion_kwargs["max_tokens"] = max_tokens
        if temperature is not None:
            completion_kwargs["temperature"] = temperature
        completion_kwargs.update(kwargs)

        response = await self._provider.complete(request_messages, **completion_kwargs)

        if self._track_usage:
            self._usage.add(response)

        self._conversation.add_message("user", self._get_last_user_message(request_messages))
        self._conversation.add_message("assistant", response.content, response.total_tokens)

        return response

    async def complete_stream(
        self,
        messages: Optional[list[LLMMessage]] = None,
        prompt: Optional[str] = None,
        system_message: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs: Any,
    ) -> AsyncGenerator[str, None]:
        """
        Stream completion from LLM.

        Args:
            messages: Optional list of messages
            prompt: Optional single prompt
            system_message: Optional system message override
            max_tokens: Optional max tokens override
            temperature: Optional temperature override
            **kwargs: Provider-specific parameters

        Yields:
            Response content chunks

        Raises:
            RuntimeError: If not connected
        """
        if not self._is_connected:
            raise RuntimeError("LLM client not connected. Call connect() first.")

        request_messages = self._build_messages(messages, prompt, system_message)

        completion_kwargs = {}
        if max_tokens is not None:
            completion_kwargs["max_tokens"] = max_tokens
        if temperature is not None:
            completion_kwargs["temperature"] = temperature
        completion_kwargs["stream"] = True
        completion_kwargs.update(kwargs)

        full_content = ""
        async for chunk in self._provider.complete_stream(request_messages, **completion_kwargs):
            full_content += chunk
            yield chunk

        self._conversation.add_message("user", self._get_last_user_message(request_messages))
        self._conversation.add_message("assistant", full_content)

    def _build_messages(
        self,
        messages: Optional[list[LLMMessage]],
        prompt: Optional[str],
        system_message: Optional[str],
    ) -> list[LLMMessage]:
        """Build message list from inputs."""
        if messages is not None:
            return messages

        if prompt is not None:
            return [LLMMessage(role="user", content=prompt)]

        if self._conversation.get_turn_count() > 0:
            return self._conversation.to_messages()

        raise ValueError("Must provide either messages, prompt, or have conversation history")

    def _get_last_user_message(self, messages: list[LLMMessage]) -> str:
        """Get last user message from list."""
        for msg in reversed(messages):
            if msg.role == "user":
                return msg.content
        return ""

    def set_system_message(self, system_message: str) -> None:
        """Set system message for conversation."""
        self._conversation.system_message = system_message

    def clear_history(self) -> None:
        """Clear conversation history."""
        self._conversation.clear()

    def reset_usage(self) -> None:
        """Reset token usage statistics."""
        self._usage = TokenUsage()

    def get_usage_summary(self) -> dict[str, Any]:
        """Get usage summary."""
        return {
            "provider": self.provider_name,
            "model": self.model,
            "usage": self._usage.to_dict(),
            "conversation_turns": self._conversation.get_turn_count(),
        }

    async def __aenter__(self) -> "LLMClient":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()


class MultiProviderClient:
    """
    Multi-provider LLM client with fallback support.

    Allows configuration of primary and fallback providers
    for improved reliability.
    """

    def __init__(
        self,
        providers: list[tuple[str, LLMProvider]],
        fallback_enabled: bool = True,
        track_usage: bool = True,
    ) -> None:
        """
        Initialize multi-provider client.

        Args:
            providers: List of (name, provider) tuples in priority order
            fallback_enabled: Enable automatic fallback on failure
            track_usage: Enable token usage tracking
        """
        self._providers = dict(providers)
        self._provider_order = [name for name, _ in providers]
        self._fallback_enabled = fallback_enabled
        self._track_usage = track_usage
        self._usage: dict[str, TokenUsage] = {name: TokenUsage() for name in self._provider_order}
        self._current_provider: Optional[str] = None
        self._is_connected = False

    @property
    def available_providers(self) -> list[str]:
        """Get list of available providers."""
        return list(self._providers.keys())

    @property
    def current_provider(self) -> Optional[str]:
        """Get current provider name."""
        return self._current_provider

    async def connect(self) -> None:
        """Connect to all providers."""
        self._is_connected = True

    async def disconnect(self) -> None:
        """Disconnect from all providers."""
        for provider in self._providers.values():
            await provider.close()
        self._is_connected = False

    async def complete(
        self,
        messages: list[LLMMessage],
        provider_name: Optional[str] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Get completion with optional fallback.

        Args:
            messages: Conversation messages
            provider_name: Optional specific provider to use
            **kwargs: Provider-specific parameters

        Returns:
            LLMResponse with completion

        Raises:
            RuntimeError: If not connected
        """
        if not self._is_connected:
            raise RuntimeError("MultiProviderClient not connected")

        if provider_name:
            return await self._complete_with_provider(provider_name, messages, **kwargs)

        for name in self._provider_order:
            try:
                response = await self._complete_with_provider(name, messages, **kwargs)
                self._current_provider = name
                return response
            except Exception:
                if not self._fallback_enabled:
                    raise
                continue

        raise RuntimeError("All providers failed")

    async def _complete_with_provider(
        self,
        provider_name: str,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> LLMResponse:
        """Complete with specific provider."""
        if provider_name not in self._providers:
            raise ValueError(f"Provider '{provider_name}' not available")

        provider = self._providers[provider_name]
        response = await provider.complete(messages, **kwargs)

        if self._track_usage:
            self._usage[provider_name].add(response)

        return response

    def get_usage(self, provider_name: Optional[str] = None) -> TokenUsage:
        """Get usage for provider or all providers."""
        if provider_name:
            return self._usage.get(provider_name, TokenUsage())

        total = TokenUsage()
        for usage in self._usage.values():
            total.prompt_tokens += usage.prompt_tokens
            total.completion_tokens += usage.completion_tokens
            total.total_tokens += usage.total_tokens
            total.request_count += usage.request_count
        return total
