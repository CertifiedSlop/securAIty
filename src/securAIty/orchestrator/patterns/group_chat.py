"""
Group Chat Pattern Implementation

Multi-agent conversation with turn-taking coordination where agents
collaborate through structured message exchange.
"""

import asyncio
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional

from ...agents.base import BaseAgent
from ...events.correlation import CorrelationContext


class TurnOrderStrategy(Enum):
    """Turn ordering strategies."""

    ROUND_ROBIN = auto()
    PRIORITY_BASED = auto()
    VOLUNTEER = auto()
    DIRECTOR_SELECTS = auto()
    TOPIC_BASED = auto()


@dataclass
class ChatMessage:
    """
    Message in group chat.

    Attributes:
        message_id: Unique message identifier
        sender_id: Sending agent ID
        content: Message content
        timestamp: Message timestamp
        in_reply_to: Parent message ID if reply
        metadata: Additional message metadata
    """

    message_id: str
    sender_id: str
    content: Any
    timestamp: float = field(default_factory=lambda: asyncio.get_event_loop().time())
    in_reply_to: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize message to dictionary."""
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "content": self.content,
            "timestamp": self.timestamp,
            "in_reply_to": self.in_reply_to,
            "metadata": self.metadata,
        }


@dataclass
class ChatState:
    """
    Current state of group chat.

    Attributes:
        chat_id: Unique chat identifier
        messages: Chat message history
        current_turn: Current turn number
        active_agents: Currently active agents
        terminated: Whether chat is terminated
        result: Final chat result if terminated
        metadata: Additional state metadata
    """

    chat_id: str
    messages: list[ChatMessage] = field(default_factory=list)
    current_turn: int = 0
    active_agents: set[str] = field(default_factory=set)
    terminated: bool = False
    result: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_message(self, message: ChatMessage) -> None:
        """Add message to history."""
        self.messages.append(message)

    def get_recent_messages(self, count: int = 10) -> list[ChatMessage]:
        """Get most recent messages."""
        return self.messages[-count:]

    def get_messages_by_agent(self, agent_id: str) -> list[ChatMessage]:
        """Get all messages from specific agent."""
        return [m for m in self.messages if m.sender_id == agent_id]


class ChatManager:
    """
    Group chat manager for multi-agent coordination.

    Coordinates turn-taking, message routing, and termination
    conditions for collaborative agent conversations.

    Attributes:
        chat_id: Chat identifier
        turn_strategy: Turn ordering strategy
        max_turns: Maximum turns before forced termination
    """

    def __init__(
        self,
        chat_id: str,
        turn_strategy: TurnOrderStrategy = TurnOrderStrategy.ROUND_ROBIN,
        max_turns: int = 50,
    ) -> None:
        """
        Initialize chat manager.

        Args:
            chat_id: Chat identifier
            turn_strategy: Turn ordering strategy
            max_turns: Maximum turns allowed
        """
        self.chat_id = chat_id
        self._turn_strategy = turn_strategy
        self._max_turns = max_turns

        self._agents: dict[str, BaseAgent] = {}
        self._agent_priorities: dict[str, int] = {}
        self._state = ChatState(chat_id=chat_id)
        self._turn_order: list[str] = []
        self._current_turn_index = 0
        self._termination_conditions: list[Callable[[ChatState], bool]] = []
        self._message_handlers: list[Callable[[ChatMessage], Any]] = []

    def add_agent(
        self,
        agent: BaseAgent,
        priority: int = 100,
    ) -> "ChatManager":
        """
        Add agent to chat.

        Args:
            agent: Agent to add
            priority: Turn priority (lower = higher priority)

        Returns:
            Self for chaining
        """
        self._agents[agent.agent_id] = agent
        self._agent_priorities[agent.agent_id] = priority
        self._state.active_agents.add(agent.agent_id)

        if self._turn_strategy == TurnOrderStrategy.ROUND_ROBIN:
            self._rebuild_turn_order()

        return self

    def remove_agent(self, agent_id: str) -> bool:
        """
        Remove agent from chat.

        Args:
            agent_id: Agent to remove

        Returns:
            True if removed
        """
        if agent_id not in self._agents:
            return False

        del self._agents[agent_id]
        del self._agent_priorities[agent_id]
        self._state.active_agents.discard(agent_id)

        if agent_id in self._turn_order:
            self._turn_order.remove(agent_id)

        return True

    def add_termination_condition(
        self,
        condition: Callable[[ChatState], bool],
    ) -> "ChatManager":
        """
        Add chat termination condition.

        Args:
            condition: Condition function

        Returns:
            Self for chaining
        """
        self._termination_conditions.append(condition)
        return self

    def add_message_handler(
        self,
        handler: Callable[[ChatMessage], Any],
    ) -> "ChatManager":
        """
        Add message handler callback.

        Args:
            handler: Message handler function

        Returns:
            Self for chaining
        """
        self._message_handlers.append(handler)
        return self

    async def start(
        self,
        initial_message: Optional[Any] = None,
        initial_context: Optional[dict[str, Any]] = None,
        correlation_context: Optional[CorrelationContext] = None,
    ) -> ChatState:
        """
        Start group chat session.

        Args:
            initial_message: Optional opening message
            initial_context: Initial context
            correlation_context: Correlation tracking

        Returns:
            Final chat state
        """
        context = initial_context or {}

        if initial_message:
            msg = ChatMessage(
                message_id=f"init_{self.chat_id}",
                sender_id="system",
                content=initial_message,
            )
            self._state.add_message(msg)

        while not self._state.terminated:
            if self._state.current_turn >= self._max_turns:
                self._state.terminated = True
                self._state.result = {"reason": "max_turns_reached"}
                break

            next_agent_id = self._select_next_agent()

            if not next_agent_id or next_agent_id not in self._agents:
                break

            agent = self._agents[next_agent_id]

            chat_history = self._format_chat_history(context)

            input_data = {
                "chat_history": chat_history,
                "current_turn": self._state.current_turn,
                "active_agents": list(self._state.active_agents),
            }

            try:
                output = await agent.execute(
                    input_data=input_data,
                    context=context,
                    correlation_context=correlation_context,
                )

                message = self._extract_message(output, next_agent_id)
                self._state.add_message(message)

                for handler in self._message_handlers:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            await handler(message)
                        else:
                            handler(message)
                    except Exception:
                        pass

                context["last_message"] = message
                context["last_speaker"] = next_agent_id

                if isinstance(output, dict):
                    if output.get("terminate"):
                        self._state.terminated = True
                        self._state.result = output.get("result")
                        break

                    if output.get("next_speaker"):
                        self._set_next_speaker(output["next_speaker"])

            except Exception as e:
                error_message = ChatMessage(
                    message_id=f"error_{self._state.current_turn}",
                    sender_id="system",
                    content={"error": str(e), "agent_id": next_agent_id},
                )
                self._state.add_message(error_message)

            self._state.current_turn += 1

            for condition in self._termination_conditions:
                if condition(self._state):
                    self._state.terminated = True
                    break

        if not self._state.result:
            self._state.result = {
                "messages": [m.to_dict() for m in self._state.messages],
                "turn_count": self._state.current_turn,
            }

        return self._state

    def _select_next_agent(self) -> Optional[str]:
        """Select next agent based on strategy."""
        if not self._state.active_agents:
            return None

        if self._turn_strategy == TurnOrderStrategy.ROUND_ROBIN:
            return self._select_round_robin()

        elif self._turn_strategy == TurnOrderStrategy.PRIORITY_BASED:
            return self._select_priority_based()

        elif self._turn_strategy == TurnOrderStrategy.VOLUNTEER:
            return self._select_volunteer()

        elif self._turn_strategy == TurnOrderStrategy.DIRECTOR_SELECTS:
            return self._select_director()

        return next(iter(self._state.active_agents))

    def _select_round_robin(self) -> Optional[str]:
        """Select next agent in round-robin order."""
        if not self._turn_order:
            self._rebuild_turn_order()

        if not self._turn_order:
            return None

        agent_id = self._turn_order[self._current_turn_index % len(self._turn_order)]
        self._current_turn_index += 1
        return agent_id

    def _select_priority_based(self) -> Optional[str]:
        """Select agent with highest priority."""
        if not self._agent_priorities:
            return None

        sorted_agents = sorted(
            self._agent_priorities.items(),
            key=lambda x: x[1],
        )

        for agent_id, _ in sorted_agents:
            if agent_id in self._state.active_agents:
                return agent_id

        return None

    def _select_volunteer(self) -> Optional[str]:
        """Select agent that volunteers (requests turn)."""
        recent_messages = self._state.get_recent_messages(3)

        if recent_messages:
            last_message = recent_messages[-1]
            if isinstance(last_message.content, dict):
                volunteers = last_message.content.get("volunteers", [])
                for volunteer in volunteers:
                    if volunteer in self._state.active_agents:
                        return volunteer

        return self._select_round_robin()

    def _select_director(self) -> Optional[str]:
        """Let director agent select next speaker."""
        if "director" in self._agents:
            director = self._agents["director"]
            return director.agent_id

        return self._select_round_robin()

    def _set_next_speaker(self, speaker_id: str) -> None:
        """Set specific next speaker."""
        if speaker_id in self._state.active_agents:
            if self._turn_strategy == TurnOrderStrategy.ROUND_ROBIN:
                try:
                    index = self._turn_order.index(speaker_id)
                    self._current_turn_index = index
                except ValueError:
                    pass

    def _rebuild_turn_order(self) -> None:
        """Rebuild turn order based on priorities."""
        sorted_agents = sorted(
            self._agent_priorities.items(),
            key=lambda x: x[1],
        )
        self._turn_order = [aid for aid, _ in sorted_agents if aid in self._state.active_agents]

    def _format_chat_history(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Format chat history for agent input."""
        return [m.to_dict() for m in self._state.get_recent_messages(20)]

    def _extract_message(self, output: Any, sender_id: str) -> ChatMessage:
        """Extract message from agent output."""
        import uuid

        if isinstance(output, dict):
            content = output.get("message", output.get("content", output))
            in_reply_to = output.get("in_reply_to")
            metadata = output.get("metadata", {})
        else:
            content = output
            in_reply_to = None
            metadata = {}

        return ChatMessage(
            message_id=str(uuid.uuid4()),
            sender_id=sender_id,
            content=content,
            in_reply_to=in_reply_to,
            metadata=metadata,
        )

    def get_state(self) -> ChatState:
        """Get current chat state."""
        return self._state

    def get_transcript(self) -> str:
        """Get chat transcript as string."""
        lines = []

        for message in self._state.messages:
            sender = message.sender_id
            content = message.content

            if isinstance(content, str):
                lines.append(f"[{sender}]: {content}")
            elif isinstance(content, dict):
                lines.append(f"[{sender}]: {content.get('message', str(content))}")
            else:
                lines.append(f"[{sender}]: {content}")

        return "\n".join(lines)
