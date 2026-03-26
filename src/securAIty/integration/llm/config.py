"""
LLM Provider Configuration

Configuration classes for LLM providers with environment variable
support and validation.
"""

import os
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class LLMProviderConfig:
    """
    Base configuration for LLM providers.

    Attributes:
        provider: Provider type identifier
        model: Model identifier to use
        api_key: API authentication key
        api_base: Base URL for API endpoint
        max_tokens: Maximum response tokens
        temperature: Response temperature (0.0-2.0)
        timeout: Request timeout in seconds
        retry_attempts: Number of retry attempts
        stream: Enable streaming responses
    """

    provider: str
    model: str
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: float = 60.0
    retry_attempts: int = 3
    stream: bool = False

    def validate(self) -> bool:
        """
        Validate configuration.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.provider:
            raise ValueError("Provider type is required")
        if not self.model:
            raise ValueError("Model is required")
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("Temperature must be between 0.0 and 2.0")
        if self.max_tokens <= 0:
            raise ValueError("Max tokens must be positive")
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")
        return True

    @classmethod
    def from_env(cls) -> "LLMProviderConfig":
        """
        Create configuration from environment variables.

        Returns:
            LLMProviderConfig instance
        """
        provider = os.environ.get("SECURAITY_LLM_PROVIDER", "ollama")
        model = os.environ.get("SECURAITY_LLM_MODEL", cls._get_default_model(provider))
        api_key = cls._get_api_key_from_env(provider)
        api_base = os.environ.get("SECURAITY_LLM_API_BASE")
        max_tokens = int(os.environ.get("SECURAITY_LLM_MAX_TOKENS", "4096"))
        temperature = float(os.environ.get("SECURAITY_LLM_TEMPERATURE", "0.7"))
        timeout = float(os.environ.get("SECURAITY_LLM_TIMEOUT", "60.0"))
        retry_attempts = int(os.environ.get("SECURAITY_LLM_RETRY_ATTEMPTS", "3"))
        stream = os.environ.get("SECURAITY_LLM_STREAM", "false").lower() == "true"

        return cls(
            provider=provider,
            model=model,
            api_key=api_key,
            api_base=api_base,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=timeout,
            retry_attempts=retry_attempts,
            stream=stream,
        )

    @staticmethod
    def _get_default_model(provider: str) -> str:
        """Get default model for provider."""
        defaults = {
            "ollama": "qwen2.5:72b",
            "openrouter": "qwen/qwen-2.5-72b-instruct",
            "gemini": "gemini-2.0-flash",
            "chatgpt": "gpt-4o",
        }
        return defaults.get(provider, "qwen2.5:72b")

    @staticmethod
    def _get_api_key_from_env(provider: str) -> Optional[str]:
        """Get API key from environment based on provider."""
        key_mapping = {
            "ollama": None,
            "openrouter": "OPENROUTER_API_KEY",
            "gemini": "GEMINI_API_KEY",
            "chatgpt": "OPENAI_API_KEY",
        }
        env_var = key_mapping.get(provider)
        if env_var:
            return os.environ.get(env_var)
        return None


@dataclass
class OllamaConfig(LLMProviderConfig):
    """
    Configuration for Ollama provider.

    Attributes:
        provider: Always "ollama"
        model: Ollama model name
        api_base: Ollama server URL
        keep_alive: How long model stays in memory
        num_predict: Maximum number of tokens to predict
        top_p: Nucleus sampling parameter
        top_k: Top-k sampling parameter
    """

    provider: str = "ollama"
    model: str = "qwen2.5:72b"
    api_base: str = "http://localhost:11434"
    api_key: Optional[str] = None
    keep_alive: str = "5m"
    num_predict: int = 4096
    top_p: float = 0.9
    top_k: int = 40
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: float = 60.0
    retry_attempts: int = 3
    stream: bool = False

    def __post_init__(self) -> None:
        self.provider = "ollama"
        if not self.api_base:
            self.api_base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

    @classmethod
    def from_env(cls) -> "OllamaConfig":
        """Create Ollama config from environment."""
        return cls(
            model=os.environ.get("SECURAITY_LLM_MODEL", "qwen2.5:72b"),
            api_base=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
            max_tokens=int(os.environ.get("SECURAITY_LLM_MAX_TOKENS", "4096")),
            temperature=float(os.environ.get("SECURAITY_LLM_TEMPERATURE", "0.7")),
            timeout=float(os.environ.get("SECURAITY_LLM_TIMEOUT", "60.0")),
            retry_attempts=int(os.environ.get("SECURAITY_LLM_RETRY_ATTEMPTS", "3")),
            stream=os.environ.get("SECURAITY_LLM_STREAM", "false").lower() == "true",
        )


@dataclass
class OpenRouterConfig(LLMProviderConfig):
    """
    Configuration for OpenRouter provider.

    Attributes:
        provider: Always "openrouter"
        model: OpenRouter model identifier
        api_key: OpenRouter API key
        api_base: OpenRouter API base URL
        site_url: Site URL for attribution
        site_name: Site name for attribution
        provider_preference: Preferred provider for model
    """

    provider: str = "openrouter"
    model: str = "qwen/qwen-2.5-72b-instruct"
    api_key: Optional[str] = None
    api_base: str = "https://openrouter.ai/api/v1"
    site_url: Optional[str] = None
    site_name: Optional[str] = None
    provider_preference: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: float = 60.0
    retry_attempts: int = 3
    stream: bool = False

    def __post_init__(self) -> None:
        self.provider = "openrouter"
        if not self.api_key:
            self.api_key = os.environ.get("OPENROUTER_API_KEY")

    @classmethod
    def from_env(cls) -> "OpenRouterConfig":
        """Create OpenRouter config from environment."""
        return cls(
            model=os.environ.get("SECURAITY_LLM_MODEL", "qwen/qwen-2.5-72b-instruct"),
            api_key=os.environ.get("OPENROUTER_API_KEY"),
            site_url=os.environ.get("OPENROUTER_SITE_URL"),
            site_name=os.environ.get("OPENROUTER_SITE_NAME"),
            provider_preference=os.environ.get("OPENROUTER_PROVIDER_PREFERENCE"),
            max_tokens=int(os.environ.get("SECURAITY_LLM_MAX_TOKENS", "4096")),
            temperature=float(os.environ.get("SECURAITY_LLM_TEMPERATURE", "0.7")),
            timeout=float(os.environ.get("SECURAITY_LLM_TIMEOUT", "60.0")),
            retry_attempts=int(os.environ.get("SECURAITY_LLM_RETRY_ATTEMPTS", "3")),
            stream=os.environ.get("SECURAITY_LLM_STREAM", "false").lower() == "true",
        )


@dataclass
class GeminiConfig(LLMProviderConfig):
    """
    Configuration for Google Gemini provider.

    Attributes:
        provider: Always "gemini"
        model: Gemini model name
        api_key: Gemini API key
        api_base: Gemini API base URL
        api_version: API version
        safety_settings: Safety category thresholds
        generation_config: Additional generation parameters
    """

    provider: str = "gemini"
    model: str = "gemini-2.0-flash"
    api_key: Optional[str] = None
    api_base: str = "https://generativelanguage.googleapis.com/v1beta"
    api_version: str = "v1beta"
    safety_settings: list[dict[str, Any]] = field(default_factory=list)
    generation_config: dict[str, Any] = field(default_factory=dict)
    max_tokens: int = 8192
    temperature: float = 0.7
    timeout: float = 60.0
    retry_attempts: int = 3
    stream: bool = False

    def __post_init__(self) -> None:
        self.provider = "gemini"
        if not self.api_key:
            self.api_key = os.environ.get("GEMINI_API_KEY")

    @classmethod
    def from_env(cls) -> "GeminiConfig":
        """Create Gemini config from environment."""
        return cls(
            model=os.environ.get("SECURAITY_LLM_MODEL", "gemini-2.0-flash"),
            api_key=os.environ.get("GEMINI_API_KEY"),
            max_tokens=int(os.environ.get("SECURAITY_LLM_MAX_TOKENS", "8192")),
            temperature=float(os.environ.get("SECURAITY_LLM_TEMPERATURE", "0.7")),
            timeout=float(os.environ.get("SECURAITY_LLM_TIMEOUT", "60.0")),
            retry_attempts=int(os.environ.get("SECURAITY_LLM_RETRY_ATTEMPTS", "3")),
            stream=os.environ.get("SECURAITY_LLM_STREAM", "false").lower() == "true",
        )


@dataclass
class ChatGPTConfig(LLMProviderConfig):
    """
    Configuration for OpenAI ChatGPT provider.

    Attributes:
        provider: Always "chatgpt"
        model: OpenAI model name
        api_key: OpenAI API key
        api_base: OpenAI API base URL
        organization: OpenAI organization ID
        project: OpenAI project ID
        presence_penalty: Presence penalty parameter
        frequency_penalty: Frequency penalty parameter
    """

    provider: str = "chatgpt"
    model: str = "gpt-4o"
    api_key: Optional[str] = None
    api_base: str = "https://api.openai.com/v1"
    organization: Optional[str] = None
    project: Optional[str] = None
    presence_penalty: float = 0.0
    frequency_penalty: float = 0.0
    max_tokens: int = 16384
    temperature: float = 0.7
    timeout: float = 60.0
    retry_attempts: int = 3
    stream: bool = False

    def __post_init__(self) -> None:
        self.provider = "chatgpt"
        if not self.api_key:
            self.api_key = os.environ.get("OPENAI_API_KEY")

    @classmethod
    def from_env(cls) -> "ChatGPTConfig":
        """Create ChatGPT config from environment."""
        return cls(
            model=os.environ.get("SECURAITY_LLM_MODEL", "gpt-4o"),
            api_key=os.environ.get("OPENAI_API_KEY"),
            organization=os.environ.get("OPENAI_ORGANIZATION"),
            project=os.environ.get("OPENAI_PROJECT"),
            max_tokens=int(os.environ.get("SECURAITY_LLM_MAX_TOKENS", "16384")),
            temperature=float(os.environ.get("SECURAITY_LLM_TEMPERATURE", "0.7")),
            timeout=float(os.environ.get("SECURAITY_LLM_TIMEOUT", "60.0")),
            retry_attempts=int(os.environ.get("SECURAITY_LLM_RETRY_ATTEMPTS", "3")),
            stream=os.environ.get("SECURAITY_LLM_STREAM", "false").lower() == "true",
        )
