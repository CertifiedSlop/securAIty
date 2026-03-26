"""
Qwen Subagent Bridge

Integration bridge for delegating tasks to LLM subagents
with context management and response processing.

This module now uses the unified LLM provider abstraction layer
for multi-provider support (Ollama, OpenRouter, Gemini, ChatGPT).
"""

import asyncio
import json
import warnings
from dataclasses import dataclass, field
from typing import Any, Optional

from ...agents.base import AgentConfig, BaseAgent
from ...events.correlation import CorrelationContext
from ..llm import (
    LLMClient,
    LLMClientConfig,
    LLMMessage,
    LLMProvider,
    LLMProviderFactory,
    LLMResponse,
    OllamaConfig,
    OllamaProvider,
    RetryConfig,
)


@dataclass
class QwenBridgeConfig:
    """
    Configuration for Qwen bridge connection.

    Attributes:
        api_endpoint: LLM API endpoint URL
        api_key: API authentication key
        model: Model identifier to use
        max_tokens: Maximum response tokens
        temperature: Response temperature
        timeout: Request timeout in seconds
        retry_attempts: Number of retry attempts (deprecated, use retry_config)
        provider: Provider type (ollama, openrouter, gemini, chatgpt)
        enable_retry: Enable persistent retry (default: True, unlimited)
        max_retries: Maximum retry attempts (-1 for unlimited)
        retry_base_delay: Base delay for retry in seconds
        retry_max_delay: Maximum delay for retry in seconds
        retry_jitter: Enable jitter for retry
    """

    api_endpoint: str = "http://localhost:11434"
    api_key: Optional[str] = None
    model: str = "qwen2.5:72b"
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: float = 60.0
    retry_attempts: int = 3
    provider: str = "ollama"
    enable_retry: bool = True
    max_retries: int = -1
    retry_base_delay: float = 1.0
    retry_max_delay: float = 60.0
    retry_jitter: bool = True

    def to_llm_config(self) -> OllamaConfig:
        """Convert to LLM provider configuration."""
        return OllamaConfig(
            api_base=self.api_endpoint,
            api_key=self.api_key,
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            timeout=self.timeout,
            retry_attempts=self.retry_attempts,
        )

    def to_retry_config(self) -> RetryConfig:
        """Convert to retry configuration."""
        return RetryConfig(
            max_retries=self.max_retries,
            base_delay=self.retry_base_delay,
            max_delay=self.retry_max_delay,
            jitter=self.retry_jitter,
        )

    def to_client_config(self) -> LLMClientConfig:
        """Convert to full LLM client configuration."""
        return LLMClientConfig(
            provider_config=self.to_llm_config(),
            retry_config=self.to_retry_config(),
            enable_retry=self.enable_retry,
            enable_circuit_breaker=False,
        )


@dataclass
class QwenMessage:
    """
    Message for Qwen conversation.

    Attributes:
        role: Message role (system, user, assistant)
        content: Message content
    """

    role: str
    content: str

    def to_llm_message(self) -> LLMMessage:
        """Convert to LLMMessage."""
        return LLMMessage(role=self.role, content=self.content)


class QwenSubAgent:
    """
    Qwen-powered subagent for delegated tasks.

    Wraps LLM provider capabilities for security analysis,
    threat intelligence, and decision support.

    Attributes:
        agent_id: Unique subagent identifier
        config: Bridge configuration
        capabilities: Declared capabilities
    """

    def __init__(
        self,
        agent_id: str,
        config: QwenBridgeConfig,
        capabilities: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        """
        Initialize Qwen subagent.

        Args:
            agent_id: Subagent identifier
            config: Bridge configuration
            capabilities: Optional capability list
        """
        self.agent_id = agent_id
        self.config = config
        self._capabilities = capabilities or [
            {"name": "security_analysis", "description": "AI-powered security analysis"},
            {"name": "threat_intelligence", "description": "Threat intelligence processing"},
            {"name": "decision_support", "description": "Security decision support"},
        ]
        self._conversation_history: list[QwenMessage] = []
        self._is_connected = False
        self._client: Optional[LLMClient] = None
        self._provider: Optional[LLMProvider] = None

    @property
    def capabilities(self) -> list[dict[str, Any]]:
        """Get subagent capabilities."""
        return self._capabilities

    async def connect(self) -> bool:
        """
        Establish connection to LLM service.

        Returns:
            True if connected successfully
        """
        try:
            client_config = self.config.to_client_config()
            self._client = LLMClient(client_config=client_config)
            await self._client.connect()

            self._is_connected = True
            self._conversation_history = [
                QwenMessage(
                    role="system",
                    content="You are a security analysis assistant. Provide accurate, actionable security insights.",
                ),
            ]
            return True
        except Exception:
            self._is_connected = False
            return False

    async def disconnect(self) -> None:
        """Disconnect from LLM service."""
        if self._client:
            await self._client.disconnect()
        self._is_connected = False
        self._conversation_history.clear()

    async def execute(
        self,
        input_data: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext] = None,
    ) -> dict[str, Any]:
        """
        Execute task using LLM.

        Args:
            input_data: Task input data
            context: Execution context
            correlation_context: Correlation tracking

        Returns:
            LLM response processed as dictionary

        Raises:
            RuntimeError: If not connected
        """
        if not self._is_connected:
            raise RuntimeError("Qwen subagent not connected")

        prompt = self._build_prompt(input_data, context)

        self._conversation_history.append(QwenMessage(role="user", content=prompt))

        response = await self._call_llm(correlation_context)

        self._conversation_history.append(
            QwenMessage(role="assistant", content=response.content)
        )

        return self._parse_response(response, input_data)

    def _build_prompt(
        self,
        input_data: dict[str, Any],
        context: dict[str, Any],
    ) -> str:
        """
        Build prompt from input and context.

        Args:
            input_data: Task input
            context: Execution context

        Returns:
            Formatted prompt string
        """
        task_type = input_data.get("task_type", "analysis")
        data = input_data.get("data", input_data)

        prompt_sections = [
            f"Task Type: {task_type}",
            f"Input Data: {json.dumps(data, indent=2)}",
        ]

        if context:
            relevant_context = {
                k: v for k, v in context.items()
                if not k.startswith("_") and isinstance(v, (str, int, float, bool, dict))
            }
            if relevant_context:
                prompt_sections.append(f"Context: {json.dumps(relevant_context, indent=2)}")

        prompt_sections.append(
            "Provide a structured response with clear findings and recommendations."
        )

        return "\n\n".join(prompt_sections)

    async def _call_llm(
        self,
        correlation_context: Optional[CorrelationContext],
    ) -> LLMResponse:
        """
        Call LLM provider.

        Args:
            correlation_context: Correlation tracking

        Returns:
            LLM response
        """
        if not self._client:
            raise RuntimeError("LLM client not initialized")

        messages = [msg.to_llm_message() for msg in self._conversation_history]

        response = await self._client.complete(messages=messages)
        return response

    def _parse_response(
        self,
        response: LLMResponse,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Parse LLM response.

        Args:
            response: Raw LLM response
            input_data: Original input data

        Returns:
            Parsed response dictionary
        """
        content = response.content

        try:
            parsed = json.loads(content)
            return {
                "success": True,
                "data": parsed,
                "tokens_used": response.total_tokens,
                "model": response.model,
                "provider": self.config.provider,
            }
        except json.JSONDecodeError:
            return {
                "success": True,
                "content": content,
                "tokens_used": response.total_tokens,
                "model": response.model,
                "provider": self.config.provider,
            }

    def clear_history(self) -> None:
        """Clear conversation history."""
        self._conversation_history = self._conversation_history[:1]

    def get_history_length(self) -> int:
        """Get conversation history length."""
        return len(self._conversation_history)

    def get_usage_stats(self) -> dict[str, Any]:
        """Get usage statistics."""
        if self._client:
            return self._client.get_usage_summary()
        return {}


class QwenBridge:
    """
    Bridge for Qwen subagent integration.

    Manages multiple Qwen subagents and provides delegation
    capabilities for security tasks.

    Uses the unified LLM provider abstraction for multi-provider support.
    """

    def __init__(self, config: Optional[QwenBridgeConfig] = None) -> None:
        """
        Initialize Qwen bridge.

        Args:
            config: Bridge configuration
        """
        self.config = config or QwenBridgeConfig()
        self._subagents: dict[str, QwenSubAgent] = {}
        self._is_connected = False

    async def connect(self) -> None:
        """Connect bridge to LLM service."""
        for subagent in self._subagents.values():
            await subagent.connect()
        self._is_connected = True

    async def disconnect(self) -> None:
        """Disconnect bridge from LLM service."""
        for subagent in self._subagents.values():
            await subagent.disconnect()
        self._is_connected = False

    def register_subagent(
        self,
        agent_id: str,
        capabilities: Optional[list[dict[str, Any]]] = None,
    ) -> QwenSubAgent:
        """
        Register a Qwen subagent.

        Args:
            agent_id: Subagent identifier
            capabilities: Optional capabilities

        Returns:
            Created subagent
        """
        subagent = QwenSubAgent(
            agent_id=agent_id,
            config=self.config,
            capabilities=capabilities,
        )

        self._subagents[agent_id] = subagent

        if self._is_connected:
            asyncio.create_task(subagent.connect())

        return subagent

    def get_subagent(self, agent_id: str) -> Optional[QwenSubAgent]:
        """
        Get subagent by ID.

        Args:
            agent_id: Subagent identifier

        Returns:
            Subagent or None
        """
        return self._subagents.get(agent_id)

    def list_subagents(self) -> list[str]:
        """
        List registered subagent IDs.

        Returns:
            List of subagent IDs
        """
        return list(self._subagents.keys())

    async def delegate(
        self,
        agent_id: str,
        task: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext] = None,
    ) -> dict[str, Any]:
        """
        Delegate task to subagent.

        Args:
            agent_id: Target subagent ID
            task: Task to delegate
            context: Task context
            correlation_context: Correlation tracking

        Returns:
            Task result

        Raises:
            KeyError: If subagent not found
        """
        if agent_id not in self._subagents:
            raise KeyError(f"Subagent '{agent_id}' not found")

        subagent = self._subagents[agent_id]

        if not subagent._is_connected:
            await subagent.connect()

        return await subagent.execute(task, context, correlation_context)

    async def broadcast(
        self,
        task: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext] = None,
    ) -> dict[str, dict[str, Any]]:
        """
        Broadcast task to all subagents.

        Args:
            task: Task to broadcast
            context: Task context
            correlation_context: Correlation tracking

        Returns:
            Results from all subagents
        """
        results = {}

        async def run_subagent(agent_id: str) -> tuple[str, dict[str, Any]]:
            try:
                result = await self.delegate(agent_id, task, context, correlation_context)
                return (agent_id, result)
            except Exception as e:
                return (agent_id, {"success": False, "error": str(e)})

        tasks = [run_subagent(agent_id) for agent_id in self._subagents]
        agent_results = await asyncio.gather(*tasks)

        for agent_id, result in agent_results:
            results[agent_id] = result

        return results

    def create_security_analyst(self) -> QwenSubAgent:
        """
        Create specialized security analyst subagent.

        Returns:
            Configured security analyst subagent
        """
        return self.register_subagent(
            agent_id="qwen_security_analyst",
            capabilities=[
                {"name": "threat_analysis", "description": "Analyze security threats"},
                {"name": "vulnerability_assessment", "description": "Assess vulnerabilities"},
                {"name": "incident_response", "description": "Support incident response"},
            ],
        )

    def create_threat_intel(self) -> QwenSubAgent:
        """
        Create specialized threat intelligence subagent.

        Returns:
            Configured threat intel subagent
        """
        return self.register_subagent(
            agent_id="qwen_threat_intel",
            capabilities=[
                {"name": "ioc_analysis", "description": "Analyze indicators of compromise"},
                {"name": "ttp_mapping", "description": "Map tactics and procedures"},
                {"name": "attribution", "description": "Threat actor attribution"},
            ],
        )

    def get_total_usage(self) -> dict[str, Any]:
        """Get total usage across all subagents."""
        total_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "request_count": 0,
        }

        for subagent in self._subagents.values():
            stats = subagent.get_usage_stats()
            usage = stats.get("usage", {})
            total_usage["prompt_tokens"] += usage.get("prompt_tokens", 0)
            total_usage["completion_tokens"] += usage.get("completion_tokens", 0)
            total_usage["total_tokens"] += usage.get("total_tokens", 0)
            total_usage["request_count"] += usage.get("request_count", 0)

        return total_usage


class QwenAgentWrapper(BaseAgent):
    """
    Wrapper for using Qwen as a securAIty agent.

    Adapts Qwen subagent to the BaseAgent interface
    for seamless integration with the orchestrator.
    """

    def __init__(
        self,
        bridge: QwenBridge,
        subagent_id: str,
        agent_config: Optional[AgentConfig] = None,
    ) -> None:
        """
        Initialize Qwen agent wrapper.

        Args:
            bridge: Qwen bridge instance
            subagent_id: Subagent to use
            agent_config: Agent configuration
        """
        if agent_config is None:
            agent_config = AgentConfig(
                agent_id=f"qwen_{subagent_id}",
                name=f"Qwen {subagent_id}",
                description="Qwen LLM-powered security agent",
                capabilities=[
                    {"name": "llm_analysis", "description": "LLM-powered analysis"},
                    {"name": "natural_language", "description": "Natural language processing"},
                ],
            )

        super().__init__(agent_config)

        self._bridge = bridge
        self._subagent_id = subagent_id

    async def _initialize(self) -> None:
        """Initialize Qwen connection."""
        if not self._bridge._is_connected:
            await self._bridge.connect()

    async def _execute(
        self,
        input_data: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Execute task using Qwen.

        Args:
            input_data: Task input
            context: Execution context
            correlation_context: Correlation tracking

        Returns:
            Qwen response
        """
        return await self._bridge.delegate(
            self._subagent_id,
            input_data,
            context,
            correlation_context,
        )


class LLMBridge(QwenBridge):
    """
    Unified LLM Bridge supporting multiple providers.

    This is an alias for QwenBridge with support for any LLM provider.
    QwenBridge is retained for backward compatibility.

    Example usage:
        bridge = LLMBridge(provider="openrouter", model="gpt-4")
        bridge = LLMBridge(provider="ollama", model="qwen2.5:72b")
        bridge = LLMBridge(provider="gemini", model="gemini-2.0-flash")
    """

    def __init__(
        self,
        provider: str = "ollama",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize LLM bridge with provider selection.

        Args:
            provider: Provider type (ollama, openrouter, gemini, chatgpt)
            model: Model identifier
            api_key: API key for provider
            api_base: API base URL
            **kwargs: Additional configuration
        """
        config = QwenBridgeConfig(
            provider=provider,
            model=model or self._get_default_model(provider),
            api_key=api_key,
            api_base=api_base or self._get_default_api_base(provider),
            **kwargs,
        )
        super().__init__(config)

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
    def _get_default_api_base(provider: str) -> str:
        """Get default API base for provider."""
        defaults = {
            "ollama": "http://localhost:11434",
            "openrouter": "https://openrouter.ai/api/v1",
            "gemini": "https://generativelanguage.googleapis.com/v1beta",
            "chatgpt": "https://api.openai.com/v1",
        }
        return defaults.get(provider, "http://localhost:11434")
