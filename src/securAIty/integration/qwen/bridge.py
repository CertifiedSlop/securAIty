"""
Qwen Subagent Bridge

Integration bridge for delegating tasks to Qwen LLM subagents
with context management and response processing.
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from ...agents.base import AgentConfig, BaseAgent
from ...events.correlation import CorrelationContext


@dataclass
class QwenBridgeConfig:
    """
    Configuration for Qwen bridge connection.

    Attributes:
        api_endpoint: Qwen API endpoint URL
        api_key: API authentication key
        model: Model identifier to use
        max_tokens: Maximum response tokens
        temperature: Response temperature
        timeout: Request timeout in seconds
        retry_attempts: Number of retry attempts
    """

    api_endpoint: str = "http://localhost:11434"
    api_key: Optional[str] = None
    model: str = "qwen-72b"
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: float = 60.0
    retry_attempts: int = 3


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


class QwenSubAgent:
    """
    Qwen-powered subagent for delegated tasks.

    Wraps Qwen LLM capabilities for security analysis,
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

    @property
    def capabilities(self) -> list[dict[str, Any]]:
        """Get subagent capabilities."""
        return self._capabilities

    async def connect(self) -> bool:
        """
        Establish connection to Qwen service.

        Returns:
            True if connected successfully
        """
        try:
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
        """Disconnect from Qwen service."""
        self._is_connected = False
        self._conversation_history.clear()

    async def execute(
        self,
        input_data: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext] = None,
    ) -> dict[str, Any]:
        """
        Execute task using Qwen.

        Args:
            input_data: Task input data
            context: Execution context
            correlation_context: Correlation tracking

        Returns:
            Qwen response processed as dictionary

        Raises:
            RuntimeError: If not connected
        """
        if not self._is_connected:
            raise RuntimeError("Qwen subagent not connected")

        prompt = self._build_prompt(input_data, context)

        self._conversation_history.append(QwenMessage(role="user", content=prompt))

        response = await self._call_qwen(correlation_context)

        self._conversation_history.append(
            QwenMessage(role="assistant", content=response.get("content", ""))
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

    async def _call_qwen(
        self,
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Call Qwen API.

        Args:
            correlation_context: Correlation tracking

        Returns:
            Qwen response
        """
        messages = [
            {"role": msg.role, "content": msg.content}
            for msg in self._conversation_history
        ]

        payload = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "stream": False,
        }

        for attempt in range(self.config.retry_attempts):
            try:
                response = await self._mock_qwen_call(payload, correlation_context)
                return response

            except Exception as e:
                if attempt == self.config.retry_attempts - 1:
                    raise
                await asyncio.sleep(0.5 * (2**attempt))

        return {"content": "", "error": "Max retries exceeded"}

    async def _mock_qwen_call(
        self,
        payload: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Mock Qwen API call for demonstration.

        In production, this would make actual HTTP requests.

        Args:
            payload: Request payload
            correlation_context: Correlation tracking

        Returns:
            Mock response
        """
        await asyncio.sleep(0.1)

        last_message = payload.get("messages", [])[-1]
        content = last_message.get("content", "")

        task_type = "analysis"
        if "Task Type:" in content:
            task_type = content.split("Task Type:")[1].split("\n")[0].strip()

        mock_responses = {
            "analysis": {
                "content": json.dumps({
                    "findings": ["Security analysis completed"],
                    "risk_level": "medium",
                    "recommendations": ["Review identified issues", "Implement recommended controls"],
                }),
                "usage": {"tokens": 100},
            },
            "threat_intelligence": {
                "content": json.dumps({
                    "threat_actors": ["Unknown"],
                    "ttps": ["reconnaissance", "initial_access"],
                    "confidence": 0.75,
                }),
                "usage": {"tokens": 80},
            },
            "decision_support": {
                "content": json.dumps({
                    "options": [
                        {"action": "remediate", "confidence": 0.85},
                        {"action": "monitor", "confidence": 0.60},
                    ],
                    "recommended": "remediate",
                }),
                "usage": {"tokens": 90},
            },
        }

        return mock_responses.get(task_type, mock_responses["analysis"])

    def _parse_response(
        self,
        response: dict[str, Any],
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Parse Qwen response.

        Args:
            response: Raw Qwen response
            input_data: Original input data

        Returns:
            Parsed response dictionary
        """
        content = response.get("content", "")

        try:
            parsed = json.loads(content)
            return {
                "success": True,
                "data": parsed,
                "tokens_used": response.get("usage", {}).get("tokens", 0),
                "model": self.config.model,
            }
        except json.JSONDecodeError:
            return {
                "success": True,
                "content": content,
                "tokens_used": response.get("usage", {}).get("tokens", 0),
                "model": self.config.model,
            }

    def clear_history(self) -> None:
        """Clear conversation history."""
        self._conversation_history = self._conversation_history[:1]

    def get_history_length(self) -> int:
        """Get conversation history length."""
        return len(self._conversation_history)


class QwenBridge:
    """
    Bridge for Qwen subagent integration.

    Manages multiple Qwen subagents and provides delegation
    capabilities for security tasks.

    Attributes:
        config: Bridge configuration
        subagents: Registered subagents
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
        """Connect bridge to Qwen service."""
        for subagent in self._subagents.values():
            await subagent.connect()
        self._is_connected = True

    async def disconnect(self) -> None:
        """Disconnect bridge from Qwen service."""
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
