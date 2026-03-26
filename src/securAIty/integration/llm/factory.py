"""
LLM Provider Factory

Factory pattern for creating LLM provider instances from configuration.
Supports runtime provider selection and switching.
"""

from typing import Any, Optional, Type

from .circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from .config import (
    ChatGPTConfig,
    GeminiConfig,
    LLMProviderConfig,
    OllamaConfig,
    OpenRouterConfig,
)
from .exceptions import LLMProviderNotAvailableError, LLMProviderValidationError
from .providers import (
    ChatGPTProvider,
    GeminiProvider,
    LLMProvider,
    OllamaProvider,
    OpenRouterProvider,
)
from .retry import PersistentRetryExecutor, RetryConfig


class LLMProviderFactory:
    """
    Factory for creating LLM provider instances.

    Supports multiple providers and allows runtime selection
    based on configuration.
    """

    _provider_registry: dict[str, tuple[Type[LLMProvider], Type[LLMProviderConfig]]] = {
        "ollama": (OllamaProvider, OllamaConfig),
        "openrouter": (OpenRouterProvider, OpenRouterConfig),
        "gemini": (GeminiProvider, GeminiConfig),
        "chatgpt": (ChatGPTProvider, ChatGPTConfig),
    }

    @classmethod
    def create(
        cls,
        provider_type: str,
        config: Optional[LLMProviderConfig] = None,
        **kwargs: Any,
    ) -> LLMProvider:
        """
        Create an LLM provider instance.

        Args:
            provider_type: Provider type identifier
            config: Optional provider configuration
            **kwargs: Additional configuration parameters

        Returns:
            Configured LLM provider instance

        Raises:
            LLMProviderNotAvailableError: If provider type is not supported
            LLMProviderValidationError: If configuration is invalid
        """
        if provider_type not in cls._provider_registry:
            available = ", ".join(cls._provider_registry.keys())
            raise LLMProviderNotAvailableError(
                f"Provider '{provider_type}' is not supported. Available: {available}",
                provider_type,
            )

        provider_class, config_class = cls._provider_registry[provider_type]

        if config is None:
            config = config_class(**kwargs)
        elif not isinstance(config, config_class):
            raise LLMProviderValidationError(
                f"Expected {config_class.__name__} for {provider_type}",
                provider_type,
            )

        config.validate()

        return provider_class(config)

    @classmethod
    def create_from_env(cls) -> LLMProvider:
        """
        Create provider from environment variables.

        Reads SECURAITY_LLM_PROVIDER and related environment
        variables to configure the provider.

        Returns:
            Configured LLM provider instance
        """
        import os

        provider_type = os.environ.get("SECURAITY_LLM_PROVIDER", "ollama")
        return cls.create(provider_type)

    @classmethod
    def register_provider(
        cls,
        provider_type: str,
        provider_class: Type[LLMProvider],
        config_class: Type[LLMProviderConfig],
    ) -> None:
        """
        Register a custom provider.

        Args:
            provider_type: Provider type identifier
            provider_class: Provider class
            config_class: Configuration class

        Raises:
            LLMProviderValidationError: If registration fails
        """
        if not issubclass(provider_class, LLMProvider):
            raise LLMProviderValidationError(
                "Provider class must inherit from LLMProvider",
            )
        if not issubclass(config_class, LLMProviderConfig):
            raise LLMProviderValidationError(
                "Config class must inherit from LLMProviderConfig",
            )

        cls._provider_registry[provider_type] = (provider_class, config_class)

    @classmethod
    def get_available_providers(cls) -> list[str]:
        """
        Get list of available provider types.

        Returns:
            List of provider type identifiers
        """
        return list(cls._provider_registry.keys())

    @classmethod
    def is_provider_available(cls, provider_type: str) -> bool:
        """
        Check if a provider type is available.

        Args:
            provider_type: Provider type identifier

        Returns:
            True if provider is available
        """
        return provider_type in cls._provider_registry

    @classmethod
    def get_provider_config_class(cls, provider_type: str) -> Type[LLMProviderConfig]:
        """
        Get configuration class for provider type.

        Args:
            provider_type: Provider type identifier

        Returns:
            Configuration class

        Raises:
            LLMProviderNotAvailableError: If provider is not available
        """
        if provider_type not in cls._provider_registry:
            available = ", ".join(cls._provider_registry.keys())
            raise LLMProviderNotAvailableError(
                f"Provider '{provider_type}' is not supported. Available: {available}",
                provider_type,
            )

        return cls._provider_registry[provider_type][1]

    @classmethod
    def wrap_with_retry(
        cls,
        provider: LLMProvider,
        max_retries: int = -1,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ) -> PersistentRetryExecutor:
        """
        Wrap a provider with persistent retry executor.

        Args:
            provider: LLM provider to wrap
            max_retries: Maximum retries (-1 for unlimited)
            base_delay: Base delay in seconds
            max_delay: Maximum delay in seconds
            exponential_base: Exponential backoff base
            jitter: Enable jitter

        Returns:
            Provider wrapped with retry executor
        """
        config = RetryConfig(
            max_retries=max_retries,
            base_delay=base_delay,
            max_delay=max_delay,
            exponential_base=exponential_base,
            jitter=jitter,
        )
        return PersistentRetryExecutor(provider, config)

    @classmethod
    def wrap_with_circuit_breaker(
        cls,
        provider: LLMProvider,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        timeout: float = 30.0,
        half_open_max_calls: int = 3,
    ) -> CircuitBreaker:
        """
        Wrap a provider with circuit breaker.

        Args:
            provider: LLM provider to wrap
            failure_threshold: Failures before opening
            success_threshold: Successes in half-open to close
            timeout: Time before transitioning to half-open
            half_open_max_calls: Max calls in half-open state

        Returns:
            Provider wrapped with circuit breaker
        """
        config = CircuitBreakerConfig(
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout,
            half_open_max_calls=half_open_max_calls,
        )
        return CircuitBreaker(provider, config)

    @classmethod
    def create_with_retry(
        cls,
        provider_type: str,
        config: Optional[LLMProviderConfig] = None,
        max_retries: int = -1,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        **kwargs: Any,
    ) -> PersistentRetryExecutor:
        """
        Create provider with automatic retry wrapping.

        Args:
            provider_type: Provider type identifier
            config: Optional provider configuration
            max_retries: Maximum retries (-1 for unlimited)
            base_delay: Base delay in seconds
            max_delay: Maximum delay in seconds
            **kwargs: Additional configuration parameters

        Returns:
            Provider with retry wrapping
        """
        provider = cls.create(provider_type, config, **kwargs)
        return cls.wrap_with_retry(
            provider,
            max_retries=max_retries,
            base_delay=base_delay,
            max_delay=max_delay,
        )

    @classmethod
    def create_with_circuit_breaker(
        cls,
        provider_type: str,
        config: Optional[LLMProviderConfig] = None,
        failure_threshold: int = 5,
        timeout: float = 30.0,
        **kwargs: Any,
    ) -> CircuitBreaker:
        """
        Create provider with circuit breaker.

        Args:
            provider_type: Provider type identifier
            config: Optional provider configuration
            failure_threshold: Failures before opening
            timeout: Time before transitioning to half-open
            **kwargs: Additional configuration parameters

        Returns:
            Provider with circuit breaker
        """
        provider = cls.create(provider_type, config, **kwargs)
        return cls.wrap_with_circuit_breaker(
            provider,
            failure_threshold=failure_threshold,
            timeout=timeout,
        )


def create_provider(
    provider_type: str,
    config: Optional[LLMProviderConfig] = None,
    **kwargs: Any,
) -> LLMProvider:
    """
    Convenience function to create LLM provider.

    Args:
        provider_type: Provider type identifier
        config: Optional provider configuration
        **kwargs: Additional configuration parameters

    Returns:
        Configured LLM provider instance
    """
    return LLMProviderFactory.create(provider_type, config, **kwargs)


def create_provider_from_env() -> LLMProvider:
    """
    Convenience function to create provider from environment.

    Returns:
        Configured LLM provider instance
    """
    return LLMProviderFactory.create_from_env()


def create_provider_with_retry(
    provider_type: str,
    config: Optional[LLMProviderConfig] = None,
    max_retries: int = -1,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    **kwargs: Any,
) -> PersistentRetryExecutor:
    """
    Convenience function to create provider with retry.

    Args:
        provider_type: Provider type identifier
        config: Optional provider configuration
        max_retries: Maximum retries (-1 for unlimited)
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        **kwargs: Additional configuration parameters

    Returns:
        Provider with retry wrapping
    """
    return LLMProviderFactory.create_with_retry(
        provider_type,
        config,
        max_retries=max_retries,
        base_delay=base_delay,
        max_delay=max_delay,
        **kwargs,
    )


def create_provider_with_circuit_breaker(
    provider_type: str,
    config: Optional[LLMProviderConfig] = None,
    failure_threshold: int = 5,
    timeout: float = 30.0,
    **kwargs: Any,
) -> CircuitBreaker:
    """
    Convenience function to create provider with circuit breaker.

    Args:
        provider_type: Provider type identifier
        config: Optional provider configuration
        failure_threshold: Failures before opening
        timeout: Time before transitioning to half-open
        **kwargs: Additional configuration parameters

    Returns:
        Provider with circuit breaker
    """
    return LLMProviderFactory.create_with_circuit_breaker(
        provider_type,
        config,
        failure_threshold=failure_threshold,
        timeout=timeout,
        **kwargs,
    )
