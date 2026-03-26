"""
LLM Providers

Abstract base class and concrete implementations for multiple LLM providers
including Ollama, OpenRouter, Gemini, and ChatGPT.
"""

import asyncio
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Optional

import aiohttp

from .config import (
    ChatGPTConfig,
    GeminiConfig,
    LLMProviderConfig,
    OllamaConfig,
    OpenRouterConfig,
)
from .exceptions import (
    ChatGPTProviderError,
    GeminiProviderError,
    LLMProviderAuthenticationError,
    LLMProviderConnectionError,
    LLMProviderError,
    LLMProviderRateLimitError,
    LLMProviderResponseError,
    LLMProviderTimeoutError,
    LLMProviderValidationError,
    OllamaProviderError,
    OpenRouterProviderError,
)


@dataclass
class LLMMessage:
    """
    Message for LLM conversation.

    Attributes:
        role: Message role (system, user, assistant)
        content: Message content
    """

    role: str
    content: str

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary."""
        return {"role": self.role, "content": self.content}


@dataclass
class LLMResponse:
    """
    Response from LLM provider.

    Attributes:
        content: Response content
        model: Model that generated the response
        usage: Token usage statistics
        finish_reason: Reason for completion
        raw_response: Raw provider response
    """

    content: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    finish_reason: Optional[str] = None
    raw_response: dict[str, Any] = field(default_factory=dict)

    @property
    def prompt_tokens(self) -> int:
        """Get prompt token count."""
        return self.usage.get("prompt_tokens", 0)

    @property
    def completion_tokens(self) -> int:
        """Get completion token count."""
        return self.usage.get("completion_tokens", 0)

    @property
    def total_tokens(self) -> int:
        """Get total token count."""
        return self.usage.get("total_tokens", 0)


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.

    All LLM providers must implement this interface to ensure
    consistent behavior across different providers.
    """

    def __init__(self, config: LLMProviderConfig) -> None:
        """
        Initialize LLM provider.

        Args:
            config: Provider configuration
        """
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get provider name."""
        pass

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Send messages and get completion response.

        Args:
            messages: List of conversation messages
            **kwargs: Additional provider-specific parameters

        Returns:
            LLMResponse with completion
        """
        pass

    @abstractmethod
    async def complete_stream(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> AsyncGenerator[str, None]:
        """
        Stream completion response.

        Args:
            messages: List of conversation messages
            **kwargs: Additional provider-specific parameters

        Yields:
            Response content chunks
        """
        pass

    @abstractmethod
    def _convert_messages(self, messages: list[LLMMessage]) -> Any:
        """Convert messages to provider-specific format."""
        pass

    @abstractmethod
    def _parse_response(self, response_data: dict[str, Any]) -> LLMResponse:
        """Parse provider response to LLMResponse."""
        pass

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> "LLMProvider":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    def _get_retry_delays(self) -> list[float]:
        """Get retry delays with exponential backoff."""
        base_delay = 1.0
        max_delay = 30.0
        delays = []
        for attempt in range(self.config.retry_attempts):
            delay = min(base_delay * (2**attempt), max_delay)
            delays.append(delay)
        return delays

    def _extract_retry_after(self, response_headers: dict[str, str]) -> Optional[float]:
        """Extract retry-after from response headers."""
        retry_after = response_headers.get("Retry-After") or response_headers.get("x-ratelimit-reset")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
        return None


class OllamaProvider(LLMProvider):
    """
    Ollama provider for local LLM inference.

    Supports local Ollama models like Qwen, Llama, Mistral, etc.
    No API key required for local deployment.
    """

    def __init__(self, config: Optional[OllamaConfig] = None) -> None:
        """
        Initialize Ollama provider.

        Args:
            config: Ollama configuration
        """
        if config is None:
            config = OllamaConfig()
        elif not isinstance(config, OllamaConfig):
            raise LLMProviderValidationError("OllamaProvider requires OllamaConfig", "ollama")
        super().__init__(config)
        self._config: OllamaConfig = config

    @property
    def provider_name(self) -> str:
        """Get provider name."""
        return "ollama"

    async def complete(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Send messages to Ollama and get completion.

        Args:
            messages: Conversation messages
            **kwargs: Additional Ollama parameters

        Returns:
            LLMResponse with completion
        """
        converted_messages = self._convert_messages(messages)
        payload = self._build_payload(converted_messages, **kwargs)
        url = f"{self._config.api_base}/api/chat"

        for attempt, delay in enumerate(self._get_retry_delays()):
            try:
                session = await self._get_session()
                async with session.post(url, json=payload) as response:
                    if response.status == 404:
                        raise OllamaProviderError(f"Model '{self._config.model}' not found")
                    if response.status != 200:
                        error_text = await response.text()
                        raise OllamaProviderError(f"Ollama API error: {error_text}")

                    response_data = await response.json()
                    return self._parse_response(response_data)

            except aiohttp.ClientConnectionError as e:
                if attempt == len(self._get_retry_delays()) - 1:
                    raise LLMProviderConnectionError(
                        f"Cannot connect to Ollama at {url}",
                        "ollama",
                        e,
                    )
                await asyncio.sleep(delay)

            except aiohttp.ClientTimeoutError as e:
                if attempt == len(self._get_retry_delays()) - 1:
                    raise LLMProviderTimeoutError(
                        f"Ollama request timed out after {self._config.timeout}s",
                        "ollama",
                        self._config.timeout,
                        e,
                    )
                await asyncio.sleep(delay)

        raise OllamaProviderError("Max retry attempts exceeded")

    async def complete_stream(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> AsyncGenerator[str, None]:
        """
        Stream completion from Ollama.

        Args:
            messages: Conversation messages
            **kwargs: Additional parameters

        Yields:
            Response content chunks
        """
        converted_messages = self._convert_messages(messages)
        payload = self._build_payload(converted_messages, stream=True, **kwargs)
        url = f"{self._config.api_base}/api/chat"

        session = await self._get_session()
        async with session.post(url, json=payload) as response:
            if response.status != 200:
                error_text = await response.text()
                raise OllamaProviderError(f"Ollama streaming error: {error_text}")

            async for line in response.content.iter_any():
                if line:
                    try:
                        chunk = json.loads(line.decode())
                        if chunk.get("message", {}).get("content"):
                            yield chunk["message"]["content"]
                    except json.JSONDecodeError:
                        continue

    def _convert_messages(self, messages: list[LLMMessage]) -> list[dict[str, str]]:
        """Convert messages to Ollama format."""
        return [{"role": msg.role, "content": msg.content} for msg in messages]

    def _parse_response(self, response_data: dict[str, Any]) -> LLMResponse:
        """Parse Ollama response."""
        message = response_data.get("message", {})
        content = message.get("content", "")

        usage = {
            "prompt_tokens": response_data.get("prompt_eval_count", 0),
            "completion_tokens": response_data.get("eval_count", 0),
            "total_tokens": response_data.get("prompt_eval_count", 0) + response_data.get("eval_count", 0),
        }

        return LLMResponse(
            content=content,
            model=response_data.get("model", self._config.model),
            usage=usage,
            finish_reason=response_data.get("done_reason"),
            raw_response=response_data,
        )

    def _build_payload(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        """Build Ollama API payload."""
        return {
            "model": self._config.model,
            "messages": messages,
            "stream": kwargs.get("stream", False),
            "options": {
                "temperature": kwargs.get("temperature", self._config.temperature),
                "num_predict": kwargs.get("num_predict", self._config.max_tokens),
                "top_p": kwargs.get("top_p", self._config.top_p),
                "top_k": kwargs.get("top_k", self._config.top_k),
            },
            "keep_alive": self._config.keep_alive,
        }


class OpenRouterProvider(LLMProvider):
    """
    OpenRouter provider for multi-model access.

    Provides access to 300+ models through a unified API
    with OpenAI-compatible interface.
    """

    def __init__(self, config: Optional[OpenRouterConfig] = None) -> None:
        """
        Initialize OpenRouter provider.

        Args:
            config: OpenRouter configuration
        """
        if config is None:
            config = OpenRouterConfig()
        elif not isinstance(config, OpenRouterConfig):
            raise LLMProviderValidationError("OpenRouterProvider requires OpenRouterConfig", "openrouter")

        if not config.api_key:
            raise LLMProviderAuthenticationError("OpenRouter API key is required", "openrouter")

        super().__init__(config)
        self._config: OpenRouterConfig = config

    @property
    def provider_name(self) -> str:
        """Get provider name."""
        return "openrouter"

    async def complete(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Send messages to OpenRouter and get completion.

        Args:
            messages: Conversation messages
            **kwargs: Additional parameters

        Returns:
            LLMResponse with completion
        """
        converted_messages = self._convert_messages(messages)
        payload = self._build_payload(converted_messages, **kwargs)
        url = f"{self._config.api_base}/chat/completions"
        headers = self._build_headers()

        for attempt, delay in enumerate(self._get_retry_delays()):
            try:
                session = await self._get_session()
                async with session.post(url, headers=headers, json=payload) as response:
                    if response.status == 401:
                        raise LLMProviderAuthenticationError("Invalid OpenRouter API key", "openrouter")
                    if response.status == 429:
                        retry_after = self._extract_retry_after(dict(response.headers))
                        raise LLMProviderRateLimitError(
                            "OpenRouter rate limit exceeded",
                            "openrouter",
                            retry_after,
                        )
                    if response.status != 200:
                        error_text = await response.text()
                        raise OpenRouterProviderError(
                            f"OpenRouter API error: {error_text}",
                            response.status,
                        )

                    response_data = await response.json()
                    return self._parse_response(response_data)

            except aiohttp.ClientConnectionError as e:
                if attempt == len(self._get_retry_delays()) - 1:
                    raise LLMProviderConnectionError("Cannot connect to OpenRouter", "openrouter", e)
                await asyncio.sleep(delay)

            except aiohttp.ClientTimeoutError as e:
                if attempt == len(self._get_retry_delays()) - 1:
                    raise LLMProviderTimeoutError(
                        "OpenRouter request timed out",
                        "openrouter",
                        self._config.timeout,
                        e,
                    )
                await asyncio.sleep(delay)

        raise OpenRouterProviderError("Max retry attempts exceeded")

    async def complete_stream(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> AsyncGenerator[str, None]:
        """
        Stream completion from OpenRouter.

        Args:
            messages: Conversation messages
            **kwargs: Additional parameters

        Yields:
            Response content chunks
        """
        converted_messages = self._convert_messages(messages)
        payload = self._build_payload(converted_messages, stream=True, **kwargs)
        url = f"{self._config.api_base}/chat/completions"
        headers = self._build_headers()

        session = await self._get_session()
        async with session.post(url, headers=headers, json=payload) as response:
            if response.status != 200:
                error_text = await response.text()
                raise OpenRouterProviderError(f"OpenRouter streaming error: {error_text}", response.status)

            async for line in response.content:
                line = line.decode().strip()
                if line.startswith("data: "):
                    data = line[6:]
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                        choice = chunk.get("choices", [{}])[0]
                        delta = choice.get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            yield content
                    except json.JSONDecodeError:
                        continue

    def _convert_messages(self, messages: list[LLMMessage]) -> list[dict[str, str]]:
        """Convert messages to OpenAI-compatible format."""
        return [{"role": msg.role, "content": msg.content} for msg in messages]

    def _parse_response(self, response_data: dict[str, Any]) -> LLMResponse:
        """Parse OpenRouter response."""
        choice = response_data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content", "")

        usage = response_data.get("usage", {})

        return LLMResponse(
            content=content,
            model=response_data.get("model", self._config.model),
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            finish_reason=choice.get("finish_reason"),
            raw_response=response_data,
        )

    def _build_payload(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        """Build OpenRouter API payload."""
        payload = {
            "model": self._config.model,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
            "temperature": kwargs.get("temperature", self._config.temperature),
            "stream": kwargs.get("stream", False),
        }

        if self._config.provider_preference:
            payload["provider"] = {"prefer": self._config.provider_preference}

        return payload

    def _build_headers(self) -> dict[str, str]:
        """Build OpenRouter request headers."""
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }

        if self._config.site_url:
            headers["HTTP-Referer"] = self._config.site_url
        if self._config.site_name:
            headers["X-Title"] = self._config.site_name

        return headers


class GeminiProvider(LLMProvider):
    """
    Google Gemini provider for Gemini models.

    Supports Gemini 1.5 and 2.0 family models with
    multi-modal capabilities.
    """

    def __init__(self, config: Optional[GeminiConfig] = None) -> None:
        """
        Initialize Gemini provider.

        Args:
            config: Gemini configuration
        """
        if config is None:
            config = GeminiConfig()
        elif not isinstance(config, GeminiConfig):
            raise LLMProviderValidationError("GeminiProvider requires GeminiConfig", "gemini")

        if not config.api_key:
            raise LLMProviderAuthenticationError("Gemini API key is required", "gemini")

        super().__init__(config)
        self._config: GeminiConfig = config

    @property
    def provider_name(self) -> str:
        """Get provider name."""
        return "gemini"

    async def complete(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Send messages to Gemini and get completion.

        Args:
            messages: Conversation messages
            **kwargs: Additional parameters

        Returns:
            LLMResponse with completion
        """
        converted_messages = self._convert_messages(messages)
        payload = self._build_payload(converted_messages, **kwargs)
        url = f"{self._config.api_base}/models/{self._config.model}:generateContent"
        params = {"key": self._config.api_key}

        for attempt, delay in enumerate(self._get_retry_delays()):
            try:
                session = await self._get_session()
                async with session.post(url, params=params, json=payload) as response:
                    if response.status == 401:
                        raise LLMProviderAuthenticationError("Invalid Gemini API key", "gemini")
                    if response.status == 429:
                        retry_after = self._extract_retry_after(dict(response.headers))
                        raise LLMProviderRateLimitError(
                            "Gemini rate limit exceeded",
                            "gemini",
                            retry_after,
                        )
                    if response.status != 200:
                        error_text = await response.text()
                        raise GeminiProviderError(
                            f"Gemini API error: {error_text}",
                            response.status,
                        )

                    response_data = await response.json()
                    return self._parse_response(response_data)

            except aiohttp.ClientConnectionError as e:
                if attempt == len(self._get_retry_delays()) - 1:
                    raise LLMProviderConnectionError("Cannot connect to Gemini API", "gemini", e)
                await asyncio.sleep(delay)

            except aiohttp.ClientTimeoutError as e:
                if attempt == len(self._get_retry_delays()) - 1:
                    raise LLMProviderTimeoutError(
                        "Gemini request timed out",
                        "gemini",
                        self._config.timeout,
                        e,
                    )
                await asyncio.sleep(delay)

        raise GeminiProviderError("Max retry attempts exceeded")

    async def complete_stream(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> AsyncGenerator[str, None]:
        """
        Stream completion from Gemini.

        Args:
            messages: Conversation messages
            **kwargs: Additional parameters

        Yields:
            Response content chunks
        """
        converted_messages = self._convert_messages(messages)
        payload = self._build_payload(converted_messages, **kwargs)
        url = f"{self._config.api_base}/models/{self._config.model}:streamGenerateContent"
        params = {"key": self._config.api_key, "alt": "sse"}

        session = await self._get_session()
        async with session.post(url, params=params, json=payload) as response:
            if response.status != 200:
                error_text = await response.text()
                raise GeminiProviderError(f"Gemini streaming error: {error_text}", response.status)

            async for line in response.content:
                line = line.decode().strip()
                if line.startswith("data: "):
                    data = line[6:]
                    try:
                        chunk = json.loads(data)
                        candidates = chunk.get("candidates", [])
                        if candidates:
                            content_parts = candidates[0].get("content", {}).get("parts", [])
                            for part in content_parts:
                                if "text" in part:
                                    yield part["text"]
                    except json.JSONDecodeError:
                        continue

    def _convert_messages(self, messages: list[LLMMessage]) -> list[dict[str, Any]]:
        """Convert messages to Gemini format."""
        contents = []
        system_instruction = None

        for msg in messages:
            if msg.role == "system":
                system_instruction = {"parts": {"text": msg.content}}
            else:
                role = "user" if msg.role == "user" else "model"
                contents.append({"role": role, "parts": [{"text": msg.content}]})

        return contents

    def _parse_response(self, response_data: dict[str, Any]) -> LLMResponse:
        """Parse Gemini response."""
        candidates = response_data.get("candidates", [])
        if not candidates:
            raise LLMProviderResponseError("No candidates in Gemini response", "gemini")

        candidate = candidates[0]
        content_parts = candidate.get("content", {}).get("parts", [])
        content = "".join(part.get("text", "") for part in content_parts)

        usage_metadata = response_data.get("usageMetadata", {})
        usage = {
            "prompt_tokens": usage_metadata.get("promptTokenCount", 0),
            "completion_tokens": usage_metadata.get("candidatesTokenCount", 0),
            "total_tokens": usage_metadata.get("totalTokenCount", 0),
        }

        return LLMResponse(
            content=content,
            model=response_data.get("modelVersion", self._config.model),
            usage=usage,
            finish_reason=candidate.get("finishReason"),
            raw_response=response_data,
        )

    def _build_payload(self, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        """Build Gemini API payload."""
        payload: dict[str, Any] = {
            "contents": messages,
            "generationConfig": {
                "temperature": kwargs.get("temperature", self._config.temperature),
                "maxOutputTokens": kwargs.get("max_tokens", self._config.max_tokens),
                "topP": 0.95,
                "topK": 40,
            },
        }

        if self._config.safety_settings:
            payload["safetySettings"] = self._config.safety_settings

        return payload


class ChatGPTProvider(LLMProvider):
    """
    OpenAI ChatGPT provider for GPT models.

    Supports GPT-4, GPT-4 Turbo, GPT-3.5 Turbo, and
    other OpenAI models.
    """

    def __init__(self, config: Optional[ChatGPTConfig] = None) -> None:
        """
        Initialize ChatGPT provider.

        Args:
            config: ChatGPT configuration
        """
        if config is None:
            config = ChatGPTConfig()
        elif not isinstance(config, ChatGPTConfig):
            raise LLMProviderValidationError("ChatGPTProvider requires ChatGPTConfig", "chatgpt")

        if not config.api_key:
            raise LLMProviderAuthenticationError("OpenAI API key is required", "chatgpt")

        super().__init__(config)
        self._config: ChatGPTConfig = config

    @property
    def provider_name(self) -> str:
        """Get provider name."""
        return "chatgpt"

    async def complete(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Send messages to ChatGPT and get completion.

        Args:
            messages: Conversation messages
            **kwargs: Additional parameters

        Returns:
            LLMResponse with completion
        """
        converted_messages = self._convert_messages(messages)
        payload = self._build_payload(converted_messages, **kwargs)
        url = f"{self._config.api_base}/chat/completions"
        headers = self._build_headers()

        for attempt, delay in enumerate(self._get_retry_delays()):
            try:
                session = await self._get_session()
                async with session.post(url, headers=headers, json=payload) as response:
                    if response.status == 401:
                        raise LLMProviderAuthenticationError("Invalid OpenAI API key", "chatgpt")
                    if response.status == 429:
                        retry_after = self._extract_retry_after(dict(response.headers))
                        raise LLMProviderRateLimitError(
                            "OpenAI rate limit exceeded",
                            "chatgpt",
                            retry_after,
                        )
                    if response.status != 200:
                        error_text = await response.text()
                        raise ChatGPTProviderError(
                            f"OpenAI API error: {error_text}",
                            response.status,
                        )

                    response_data = await response.json()
                    return self._parse_response(response_data)

            except aiohttp.ClientConnectionError as e:
                if attempt == len(self._get_retry_delays()) - 1:
                    raise LLMProviderConnectionError("Cannot connect to OpenAI API", "chatgpt", e)
                await asyncio.sleep(delay)

            except aiohttp.ClientTimeoutError as e:
                if attempt == len(self._get_retry_delays()) - 1:
                    raise LLMProviderTimeoutError(
                        "OpenAI request timed out",
                        "chatgpt",
                        self._config.timeout,
                        e,
                    )
                await asyncio.sleep(delay)

        raise ChatGPTProviderError("Max retry attempts exceeded")

    async def complete_stream(
        self,
        messages: list[LLMMessage],
        **kwargs: Any,
    ) -> AsyncGenerator[str, None]:
        """
        Stream completion from ChatGPT.

        Args:
            messages: Conversation messages
            **kwargs: Additional parameters

        Yields:
            Response content chunks
        """
        converted_messages = self._convert_messages(messages)
        payload = self._build_payload(converted_messages, stream=True, **kwargs)
        url = f"{self._config.api_base}/chat/completions"
        headers = self._build_headers()

        session = await self._get_session()
        async with session.post(url, headers=headers, json=payload) as response:
            if response.status != 200:
                error_text = await response.text()
                raise ChatGPTProviderError(f"OpenAI streaming error: {error_text}", response.status)

            async for line in response.content:
                line = line.decode().strip()
                if line.startswith("data: "):
                    data = line[6:]
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                        choice = chunk.get("choices", [{}])[0]
                        delta = choice.get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            yield content
                    except json.JSONDecodeError:
                        continue

    def _convert_messages(self, messages: list[LLMMessage]) -> list[dict[str, str]]:
        """Convert messages to OpenAI format."""
        return [{"role": msg.role, "content": msg.content} for msg in messages]

    def _parse_response(self, response_data: dict[str, Any]) -> LLMResponse:
        """Parse OpenAI response."""
        choice = response_data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content", "")

        usage = response_data.get("usage", {})

        return LLMResponse(
            content=content,
            model=response_data.get("model", self._config.model),
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            finish_reason=choice.get("finish_reason"),
            raw_response=response_data,
        )

    def _build_payload(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        """Build OpenAI API payload."""
        return {
            "model": self._config.model,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
            "temperature": kwargs.get("temperature", self._config.temperature),
            "stream": kwargs.get("stream", False),
            "presence_penalty": kwargs.get("presence_penalty", self._config.presence_penalty),
            "frequency_penalty": kwargs.get("frequency_penalty", self._config.frequency_penalty),
        }

    def _build_headers(self) -> dict[str, str]:
        """Build OpenAI request headers."""
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }

        if self._config.organization:
            headers["OpenAI-Organization"] = self._config.organization
        if self._config.project:
            headers["OpenAI-Project"] = self._config.project

        return headers
