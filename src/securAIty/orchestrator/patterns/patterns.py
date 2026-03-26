"""
Orchestration patterns for security agent coordination.

Implements various patterns for coordinating multiple agents including
Sequential, Concurrent, Handoff, GroupChat, and Magentic patterns.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from securAIty.agents.base import BaseAgent, TaskRequest, TaskResult
from securAIty.events.schema import SecurityEvent


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PatternContext:
    """Context information for pattern execution."""

    pattern_id: str
    pattern_type: str
    correlation_id: Optional[str]
    started_at: datetime
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class PatternResult:
    """Result of pattern execution."""

    success: bool
    pattern_id: str
    pattern_type: str
    task_results: list[TaskResult]
    events_generated: list[SecurityEvent]
    total_execution_time_seconds: float
    error_message: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class OrchestrationPattern(ABC):
    """
    Abstract base class for orchestration patterns.

    Defines the interface for all orchestration patterns that coordinate
    multiple agents in various execution patterns.
    """

    def __init__(self, pattern_id: Optional[str] = None) -> None:
        """
        Initialize the orchestration pattern.

        Args:
            pattern_id: Optional unique identifier for the pattern
        """
        import uuid

        self._pattern_id = pattern_id or str(uuid.uuid4())
        self._is_executing = False

    @property
    def pattern_id(self) -> str:
        """Get the pattern ID."""
        return self._pattern_id

    @property
    @abstractmethod
    def pattern_type(self) -> str:
        """Get the pattern type name."""
        pass

    @property
    def is_executing(self) -> bool:
        """Check if pattern is currently executing."""
        return self._is_executing

    async def execute(
        self,
        agents: list[BaseAgent],
        tasks: list[TaskRequest],
        correlation_id: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> PatternResult:
        """
        Execute the orchestration pattern.

        Args:
            agents: List of agents to coordinate
            tasks: List of tasks to execute
            correlation_id: Optional correlation ID for tracking
            context: Optional execution context

        Returns:
            PatternResult with execution outcome
        """
        import time

        if not agents:
            return PatternResult(
                success=False,
                pattern_id=self._pattern_id,
                pattern_type=self.pattern_type,
                task_results=[],
                events_generated=[],
                total_execution_time_seconds=0,
                error_message="No agents provided",
            )

        if not tasks:
            return PatternResult(
                success=False,
                pattern_id=self._pattern_id,
                pattern_type=self.pattern_type,
                task_results=[],
                events_generated=[],
                total_execution_time_seconds=0,
                error_message="No tasks provided",
            )

        self._is_executing = True
        start_time = time.perf_counter()

        pattern_context = PatternContext(
            pattern_id=self._pattern_id,
            pattern_type=self.pattern_type,
            correlation_id=correlation_id,
            started_at=datetime.now(timezone.utc),
            context=context or {},
        )

        try:
            result = await self._do_execute(
                agents=agents,
                tasks=tasks,
                pattern_context=pattern_context,
            )

            execution_time = time.perf_counter() - start_time
            self._is_executing = False

            return PatternResult(
                success=result.success,
                pattern_id=self._pattern_id,
                pattern_type=self.pattern_type,
                task_results=result.task_results,
                events_generated=result.events_generated,
                total_execution_time_seconds=execution_time,
                error_message=result.error_message,
                metadata=result.metadata,
            )

        except Exception as error:
            execution_time = time.perf_counter() - start_time
            self._is_executing = False

            logger.exception("Pattern execution failed: %s", error)

            return PatternResult(
                success=False,
                pattern_id=self._pattern_id,
                pattern_type=self.pattern_type,
                task_results=[],
                events_generated=[],
                total_execution_time_seconds=execution_time,
                error_message=str(error),
            )

    @abstractmethod
    async def _do_execute(
        self,
        agents: list[BaseAgent],
        tasks: list[TaskRequest],
        pattern_context: PatternContext,
    ) -> PatternResult:
        """
        Execute the pattern-specific logic.

        Args:
            agents: List of agents to coordinate
            tasks: List of tasks to execute
            pattern_context: Pattern execution context

        Returns:
            PatternResult with execution outcome
        """
        pass


class SequentialPattern(OrchestrationPattern):
    """
    Sequential orchestration pattern.

    Executes tasks one after another in order, with each task waiting
    for the previous task to complete before starting.
    """

    @property
    def pattern_type(self) -> str:
        """Get the pattern type name."""
        return "sequential"

    async def _do_execute(
        self,
        agents: list[BaseAgent],
        tasks: list[TaskRequest],
        pattern_context: PatternContext,
    ) -> PatternResult:
        """Execute tasks sequentially."""
        task_results = []
        events_generated = []

        for idx, task in enumerate(tasks):
            agent = agents[idx % len(agents)]

            logger.info(
                "Sequential pattern: Executing task %d/%d with agent %s",
                idx + 1,
                len(tasks),
                agent.agent_id,
            )

            result = await agent.execute(task)
            task_results.append(result)

            if result.is_failure:
                logger.warning(
                    "Sequential pattern: Task %d failed, stopping execution",
                    idx + 1,
                )
                return PatternResult(
                    success=False,
                    pattern_id=self._pattern_id,
                    pattern_type=self.pattern_type,
                    task_results=task_results,
                    events_generated=events_generated,
                    total_execution_time_seconds=0,
                    error_message=f"Task {idx + 1} failed: {result.error_message}",
                    metadata={"failed_at_step": idx + 1},
                )

        return PatternResult(
            success=True,
            pattern_id=self._pattern_id,
            pattern_type=self.pattern_type,
            task_results=task_results,
            events_generated=events_generated,
            total_execution_time_seconds=0,
        )


class ConcurrentPattern(OrchestrationPattern):
    """
    Concurrent orchestration pattern.

    Executes multiple tasks simultaneously across available agents,
    collecting all results when complete.
    """

    def __init__(
        self,
        pattern_id: Optional[str] = None,
        max_concurrent: Optional[int] = None,
    ) -> None:
        """
        Initialize the concurrent pattern.

        Args:
            pattern_id: Optional unique identifier
            max_concurrent: Maximum concurrent executions
        """
        super().__init__(pattern_id)
        self._max_concurrent = max_concurrent

    @property
    def pattern_type(self) -> str:
        """Get the pattern type name."""
        return "concurrent"

    async def _do_execute(
        self,
        agents: list[BaseAgent],
        tasks: list[TaskRequest],
        pattern_context: PatternContext,
    ) -> PatternResult:
        """Execute tasks concurrently."""
        task_results = []
        events_generated = []

        semaphore = None
        if self._max_concurrent:
            semaphore = asyncio.Semaphore(self._max_concurrent)

        async def execute_task(
            task: TaskRequest,
            agent: BaseAgent,
            task_index: int,
        ) -> tuple[int, TaskResult]:
            if semaphore:
                async with semaphore:
                    result = await agent.execute(task)
            else:
                result = await agent.execute(task)
            return (task_index, result)

        agent_assignments = []
        for idx, task in enumerate(tasks):
            agent = agents[idx % len(agents)]
            agent_assignments.append((idx, task, agent))

        coroutines = [
            execute_task(task, agent, idx) for idx, task, agent in agent_assignments
        ]

        results = await asyncio.gather(*coroutines, return_exceptions=True)

        sorted_results: list[tuple[int, TaskResult]] = []
        for result in results:
            if isinstance(result, Exception):
                logger.exception("Concurrent task failed with exception: %s", result)
            elif isinstance(result, tuple):
                sorted_results.append(result)

        sorted_results.sort(key=lambda x: x[0])
        task_results = [result for _, result in sorted_results]

        all_success = all(r.is_success for r in task_results)

        return PatternResult(
            success=all_success,
            pattern_id=self._pattern_id,
            pattern_type=self.pattern_type,
            task_results=task_results,
            events_generated=events_generated,
            total_execution_time_seconds=0,
        )


class HandoffPattern(OrchestrationPattern):
    """
    Handoff orchestration pattern.

    Passes tasks between agents in a chain, where each agent's output
    becomes the next agent's input.
    """

    @property
    def pattern_type(self) -> str:
        """Get the pattern type name."""
        return "handoff"

    async def _do_execute(
        self,
        agents: list[BaseAgent],
        tasks: list[TaskRequest],
        pattern_context: PatternContext,
    ) -> PatternResult:
        """Execute tasks in handoff pattern."""
        if len(agents) < 2:
            return PatternResult(
                success=False,
                pattern_id=self._pattern_id,
                pattern_type=self.pattern_type,
                task_results=[],
                events_generated=[],
                total_execution_time_seconds=0,
                error_message="Handoff pattern requires at least 2 agents",
            )

        task_results = []
        events_generated = []
        current_context = pattern_context.context.copy()

        for idx, (agent, task) in enumerate(zip(agents, tasks)):
            logger.info(
                "Handoff pattern: Passing to agent %d/%d (%s)",
                idx + 1,
                len(agents),
                agent.agent_id,
            )

            task_with_context = TaskRequest(
                task_id=task.task_id,
                task_type=task.task_type,
                description=task.description,
                parameters={**task.parameters, **current_context},
                requested_capabilities=task.requested_capabilities,
                priority=task.priority,
                timeout_seconds=task.timeout_seconds,
                correlation_id=task.correlation_id,
                parent_task_id=task.parent_task_id,
                context=current_context,
                created_at=task.created_at,
            )

            result = await agent.execute(task_with_context)
            task_results.append(result)

            if result.is_failure:
                logger.warning(
                    "Handoff pattern: Agent %d failed, stopping handoff",
                    idx + 1,
                )
                return PatternResult(
                    success=False,
                    pattern_id=self._pattern_id,
                    pattern_type=self.pattern_type,
                    task_results=task_results,
                    events_generated=events_generated,
                    total_execution_time_seconds=0,
                    error_message=f"Agent {idx + 1} failed: {result.error_message}",
                    metadata={"failed_at_step": idx + 1},
                )

            current_context.update(result.output)

        return PatternResult(
            success=True,
            pattern_id=self._pattern_id,
            pattern_type=self.pattern_type,
            task_results=task_results,
            events_generated=events_generated,
            total_execution_time_seconds=0,
            metadata={"final_context": current_context},
        )


class GroupChatPattern(OrchestrationPattern):
    """
    GroupChat orchestration pattern.

    Enables multiple agents to collaborate on a task by sharing
    intermediate results and building consensus.
    """

    def __init__(
        self,
        pattern_id: Optional[str] = None,
        max_rounds: int = 3,
        consensus_threshold: float = 0.7,
    ) -> None:
        """
        Initialize the group chat pattern.

        Args:
            pattern_id: Optional unique identifier
            max_rounds: Maximum discussion rounds
            consensus_threshold: Threshold for consensus (0.0-1.0)
        """
        super().__init__(pattern_id)
        self._max_rounds = max_rounds
        self._consensus_threshold = consensus_threshold

    @property
    def pattern_type(self) -> str:
        """Get the pattern type name."""
        return "group_chat"

    async def _do_execute(
        self,
        agents: list[BaseAgent],
        tasks: list[TaskRequest],
        pattern_context: PatternContext,
    ) -> PatternResult:
        """Execute tasks in group chat pattern."""
        task_results = []
        events_generated = []
        shared_context = pattern_context.context.copy()
        agent_contributions: dict[str, list[dict[str, Any]]] = {
            agent.agent_id: [] for agent in agents
        }

        primary_task = tasks[0] if tasks else None
        if not primary_task:
            return PatternResult(
                success=False,
                pattern_id=self._pattern_id,
                pattern_type=self.pattern_type,
                task_results=[],
                events_generated=[],
                total_execution_time_seconds=0,
                error_message="No primary task provided",
            )

        for round_num in range(self._max_rounds):
            logger.info(
                "GroupChat pattern: Starting round %d/%d",
                round_num + 1,
                self._max_rounds,
            )

            round_tasks = []
            for idx, agent in enumerate(agents):
                task = TaskRequest(
                    task_id=primary_task.task_id,
                    task_type=primary_task.task_type,
                    description=f"{primary_task.description} (Round {round_num + 1})",
                    parameters={**primary_task.parameters, **shared_context},
                    requested_capabilities=primary_task.requested_capabilities,
                    priority=primary_task.priority,
                    timeout_seconds=primary_task.timeout_seconds / self._max_rounds,
                    correlation_id=primary_task.correlation_id,
                    context={
                        **shared_context,
                        "round": round_num + 1,
                        "contributions": agent_contributions,
                    },
                    created_at=primary_task.created_at,
                )
                round_tasks.append((agent, task))

            results = await asyncio.gather(
                *[agent.execute(task) for agent, task in round_tasks],
                return_exceptions=True,
            )

            round_success = 0
            for idx, result in enumerate(results):
                if isinstance(result, TaskResult) and result.is_success:
                    round_success += 1
                    task_results.append(result)
                    agent_contributions[agents[idx].agent_id].append(result.output)
                    shared_context.update(result.output)
                elif isinstance(result, Exception):
                    logger.exception("Agent %d failed: %s", idx, result)

            consensus_ratio = round_success / len(agents)

            if consensus_ratio >= self._consensus_threshold:
                logger.info(
                    "GroupChat pattern: Consensus reached (%.1f%%)",
                    consensus_ratio * 100,
                )
                break

            if round_num == self._max_rounds - 1:
                logger.warning(
                    "GroupChat pattern: No consensus after %d rounds",
                    self._max_rounds,
                )

        return PatternResult(
            success=True,
            pattern_id=self._pattern_id,
            pattern_type=self.pattern_type,
            task_results=task_results,
            events_generated=events_generated,
            total_execution_time_seconds=0,
            metadata={
                "rounds_completed": len(task_results) // len(agents),
                "consensus_achieved": consensus_ratio >= self._consensus_threshold,
                "agent_contributions": agent_contributions,
            },
        )


class MagenticPattern(OrchestrationPattern):
    """
    Magentic (Magnetic) orchestration pattern.

    Uses a central orchestrator agent that attracts and delegates tasks
    to specialized agents based on their capabilities.
    """

    def __init__(
        self,
        pattern_id: Optional[str] = None,
        orchestrator_agent_id: Optional[str] = None,
    ) -> None:
        """
        Initialize the magentic pattern.

        Args:
            pattern_id: Optional unique identifier
            orchestrator_agent_id: ID of the orchestrator agent
        """
        super().__init__(pattern_id)
        self._orchestrator_agent_id = orchestrator_agent_id

    @property
    def pattern_type(self) -> str:
        """Get the pattern type name."""
        return "magentic"

    async def _do_execute(
        self,
        agents: list[BaseAgent],
        tasks: list[TaskRequest],
        pattern_context: PatternContext,
    ) -> PatternResult:
        """Execute tasks in magentic pattern."""
        task_results = []
        events_generated = []

        orchestrator = None
        if self._orchestrator_agent_id:
            orchestrator = next(
                (a for a in agents if a.agent_id == self._orchestrator_agent_id),
                None,
            )

        if not orchestrator:
            orchestrator = agents[0] if agents else None

        if not orchestrator:
            return PatternResult(
                success=False,
                pattern_id=self._pattern_id,
                pattern_type=self.pattern_type,
                task_results=[],
                events_generated=[],
                total_execution_time_seconds=0,
                error_message="No orchestrator agent available",
            )

        specialized_agents = [a for a in agents if a != orchestrator]

        for idx, task in enumerate(tasks):
            logger.info(
                "Magentic pattern: Orchestrator delegating task %d/%d",
                idx + 1,
                len(tasks),
            )

            selected_agent = await self._select_specialized_agent(
                orchestrator=orchestrator,
                specialized_agents=specialized_agents,
                task=task,
            )

            if not selected_agent:
                selected_agent = orchestrator

            result = await selected_agent.execute(task)
            task_results.append(result)

            logger.info(
                "Magentic pattern: Task %d executed by agent %s",
                idx + 1,
                selected_agent.agent_id,
            )

        all_success = all(r.is_success for r in task_results)

        return PatternResult(
            success=all_success,
            pattern_id=self._pattern_id,
            pattern_type=self.pattern_type,
            task_results=task_results,
            events_generated=events_generated,
            total_execution_time_seconds=0,
            metadata={
                "orchestrator_id": orchestrator.agent_id,
                "specialized_agents_count": len(specialized_agents),
            },
        )

    async def _select_specialized_agent(
        self,
        orchestrator: BaseAgent,
        specialized_agents: list[BaseAgent],
        task: TaskRequest,
    ) -> Optional[BaseAgent]:
        """Select the best specialized agent for a task."""
        if not specialized_agents:
            return None

        if not task.requested_capabilities:
            return specialized_agents[0]

        best_agent = None
        best_score = 0

        for agent in specialized_agents:
            score = sum(
                1
                for cap in task.requested_capabilities
                if agent.metadata.has_capability(cap)
            )
            if score > best_score:
                best_score = score
                best_agent = agent

        return best_agent
