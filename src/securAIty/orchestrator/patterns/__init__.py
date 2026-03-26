"""
Orchestration Patterns

Multi-agent orchestration patterns for security workflows.
"""

from .sequential import SequentialExecutor, SequentialStep
from .concurrent import ConcurrentExecutor, ConcurrentTask, ResultAggregator, TaskResult
from .handoff import HandoffOrchestrator, HandoffAgent, HandoffTarget, HandoffResult, HandoffDecision
from .group_chat import ChatManager, ChatState, ChatMessage, TurnOrderStrategy
from .magentic import MagenticManager, Plan, SubTask, TaskStatus

__all__ = [
    "SequentialExecutor",
    "SequentialStep",
    "ConcurrentExecutor",
    "ConcurrentTask",
    "ResultAggregator",
    "TaskResult",
    "HandoffOrchestrator",
    "HandoffAgent",
    "HandoffTarget",
    "HandoffResult",
    "HandoffDecision",
    "ChatManager",
    "ChatState",
    "ChatMessage",
    "TurnOrderStrategy",
    "MagenticManager",
    "Plan",
    "SubTask",
    "TaskStatus",
]
