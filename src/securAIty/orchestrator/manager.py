"""
Security Orchestrator Manager

Main orchestrator class coordinating multi-agent security workflows
with support for multiple orchestration patterns and lifecycle management.
"""

import asyncio
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from ..agents.base import BaseAgent
from ..events.bus import EventBus, EventBusConfig
from ..events.correlation import CorrelationTracker, get_tracker
from ..events.schema import EventStatus, EventType, SecurityEvent, Severity
from .policy_engine import PolicyEngine
from .state_manager import StateCheckpoint, StateManager
from .task_router import RoutingDecision, TaskRouter


class OrchestratorStatus(Enum):
    """Orchestrator lifecycle status."""

    STOPPED = auto()
    STARTING = auto()
    RUNNING = auto()
    PAUSED = auto()
    STOPPING = auto()
    ERROR = auto()


class OrchestrationPattern(Enum):
    """Supported orchestration patterns."""

    SEQUENTIAL = "sequential"
    CONCURRENT = "concurrent"
    HANDOFF = "handoff"
    GROUP_CHAT = "group_chat"
    MAGENTIC = "magentic"


@dataclass
class OrchestratorConfig:
    """
    Configuration for security orchestrator.

    Attributes:
        orchestrator_id: Unique orchestrator identifier
        pattern: Orchestration pattern to use
        max_concurrent_tasks: Maximum parallel task execution
        task_timeout_seconds: Default task timeout
        max_retries: Maximum task retry attempts
        enable_policy_enforcement: Enable policy checks
        enable_state_persistence: Enable checkpointing
        state_checkpoint_interval: Checkpoint frequency
        event_bus_config: NATS event bus configuration
    """

    orchestrator_id: str = "orchestrator_001"
    pattern: OrchestrationPattern = OrchestrationPattern.SEQUENTIAL
    max_concurrent_tasks: int = 10
    task_timeout_seconds: float = 300.0
    max_retries: int = 3
    enable_policy_enforcement: bool = True
    enable_state_persistence: bool = True
    state_checkpoint_interval: int = 10
    event_bus_config: Optional[EventBusConfig] = None

    def __post_init__(self) -> None:
        if self.event_bus_config is None:
            self.event_bus_config = EventBusConfig()


@dataclass
class TaskResult:
    """
    Result from task execution.

    Attributes:
        task_id: Unique task identifier
        agent_id: Executing agent identifier
        success: Whether task succeeded
        output: Task output data
        error: Error message if failed
        duration_seconds: Execution time
        retry_count: Number of retry attempts
    """

    task_id: str
    agent_id: str
    success: bool
    output: Any = None
    error: Optional[str] = None
    duration_seconds: float = 0.0
    retry_count: int = 0


@dataclass
class WorkflowState:
    """
    Current workflow execution state.

    Attributes:
        workflow_id: Unique workflow identifier
        pattern: Orchestration pattern
        status: Current execution status
        current_step: Current step index
        total_steps: Total workflow steps
        results: Task results by ID
        context: Shared workflow context
        created_at: Workflow start time
        updated_at: Last update time
    """

    workflow_id: str
    pattern: OrchestrationPattern
    status: OrchestratorStatus = OrchestratorStatus.STOPPED
    current_step: int = 0
    total_steps: int = 0
    results: dict[str, TaskResult] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=lambda: asyncio.get_event_loop().time())
    updated_at: float = field(default_factory=lambda: asyncio.get_event_loop().time())


class SecurityOrchestrator:
    """
    Main orchestrator for multi-agent security workflows.

    Coordinates agent execution according to orchestration patterns,
    manages task routing, enforces policies, and maintains state.

    Attributes:
        config: Orchestrator configuration
        event_bus: NATS event bus for communication
        task_router: Capability-based task router
        policy_engine: Policy evaluation engine
        state_manager: State persistence manager
        correlation_tracker: Distributed tracing
    """

    def __init__(
        self,
        config: Optional[OrchestratorConfig] = None,
        event_bus: Optional[EventBus] = None,
    ) -> None:
        """
        Initialize security orchestrator.

        Args:
            config: Orchestrator configuration
            event_bus: Optional pre-configured event bus
        """
        self.config = config or OrchestratorConfig()
        self.event_bus = event_bus or EventBus(self.config.event_bus_config)
        self.task_router = TaskRouter()
        self.policy_engine = PolicyEngine()
        self.state_manager = StateManager(
            orchestrator_id=self.config.orchestrator_id,
            checkpoint_interval=self.config.state_checkpoint_interval,
        )
        self.correlation_tracker = get_tracker()

        self._agents: dict[str, BaseAgent] = {}
        self._workflows: dict[str, WorkflowState] = {}
        self._status = OrchestratorStatus.STOPPED
        self._task_semaphore: Optional[asyncio.Semaphore] = None
        self._shutdown_event = asyncio.Event()

    def register_agent(self, agent: BaseAgent) -> str:
        """
        Register an agent for task execution.

        Args:
            agent: Agent instance to register

        Returns:
            Agent identifier

        Raises:
            ValueError: If agent already registered
        """
        agent_id = agent.agent_id

        if agent_id in self._agents:
            raise ValueError(f"Agent '{agent_id}' already registered")

        self._agents[agent_id] = agent
        self.task_router.register_agent(agent)

        return agent_id

    def unregister_agent(self, agent_id: str) -> bool:
        """
        Remove agent from registry.

        Args:
            agent_id: Agent identifier to remove

        Returns:
            True if removed, False if not found
        """
        if agent_id not in self._agents:
            return False

        del self._agents[agent_id]
        self.task_router.unregister_agent(agent_id)

        return True

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """
        Get agent by identifier.

        Args:
            agent_id: Agent identifier

        Returns:
            Agent instance or None
        """
        return self._agents.get(agent_id)

    def list_agents(self) -> list[str]:
        """
        Get all registered agent identifiers.

        Returns:
            List of agent IDs
        """
        return list(self._agents.keys())

    async def start(self) -> None:
        """
        Start the orchestrator.

        Initializes event bus connection and sets status to running.
        """
        if self._status != OrchestratorStatus.STOPPED:
            return

        self._status = OrchestratorStatus.STARTING
        self._task_semaphore = asyncio.Semaphore(self.config.max_concurrent_tasks)

        try:
            await self.event_bus.connect()
            self._status = OrchestratorStatus.RUNNING
            self._shutdown_event.clear()

            await self._emit_event(
                EventType.SYSTEM_HEALTH_CHECK,
                Severity.INFO,
                "Orchestrator started",
                {"orchestrator_id": self.config.orchestrator_id},
            )

        except Exception as e:
            self._status = OrchestratorStatus.ERROR
            raise RuntimeError(f"Failed to start orchestrator: {e}") from e

    async def stop(self) -> None:
        """
        Stop the orchestrator gracefully.

        Cancels active workflows and disconnects event bus.
        """
        if self._status not in (OrchestratorStatus.RUNNING, OrchestratorStatus.PAUSED):
            return

        self._status = OrchestratorStatus.STOPPING
        self._shutdown_event.set()

        for workflow in self._workflows.values():
            workflow.status = OrchestratorStatus.STOPPING

        await self.event_bus.disconnect()

        if self.config.enable_state_persistence:
            await self.state_manager.save_checkpoint(
                StateCheckpoint(
                    checkpoint_id="shutdown",
                    orchestrator_status=self._status.name,
                    workflow_states={
                        wid: {
                            "workflow_id": w.workflow_id,
                            "pattern": w.pattern.value,
                            "status": w.status.name,
                            "current_step": w.current_step,
                            "results": {
                                tid: {
                                    "task_id": r.task_id,
                                    "agent_id": r.agent_id,
                                    "success": r.success,
                                    "output": r.output,
                                }
                                for tid, r in w.results.items()
                            },
                        }
                        for wid, w in self._workflows.items()
                    },
                )
            )

        self._status = OrchestratorStatus.STOPPED

        await self._emit_event(
            EventType.SYSTEM_HEALTH_CHECK,
            Severity.INFO,
            "Orchestrator stopped",
            {"orchestrator_id": self.config.orchestrator_id},
        )

    async def execute_workflow(
        self,
        workflow_id: str,
        tasks: list[dict[str, Any]],
        initial_context: Optional[dict[str, Any]] = None,
    ) -> WorkflowState:
        """
        Execute a workflow with multiple tasks.

        Args:
            workflow_id: Unique workflow identifier
            tasks: List of task definitions
            initial_context: Initial shared context

        Returns:
            Final workflow state

        Raises:
            RuntimeError: If orchestrator not running
        """
        if self._status != OrchestratorStatus.RUNNING:
            raise RuntimeError("Orchestrator not running")

        workflow = WorkflowState(
            workflow_id=workflow_id,
            pattern=self.config.pattern,
            status=OrchestratorStatus.RUNNING,
            total_steps=len(tasks),
            context=initial_context or {},
        )

        self._workflows[workflow_id] = workflow

        correlation_context = self.correlation_tracker.start_correlation(
            correlation_id=workflow_id,
            baggage={"workflow_id": workflow_id, "pattern": self.config.pattern.value},
        )

        try:
            if self.config.pattern == OrchestrationPattern.SEQUENTIAL:
                await self._execute_sequential(workflow, tasks, correlation_context)

            elif self.config.pattern == OrchestrationPattern.CONCURRENT:
                await self._execute_concurrent(workflow, tasks, correlation_context)

            elif self.config.pattern == OrchestrationPattern.HANDOFF:
                await self._execute_handoff(workflow, tasks, correlation_context)

            elif self.config.pattern == OrchestrationPattern.GROUP_CHAT:
                await self._execute_group_chat(workflow, tasks, correlation_context)

            elif self.config.pattern == OrchestrationPattern.MAGENTIC:
                await self._execute_magentic(workflow, tasks, correlation_context)

            workflow.status = OrchestratorStatus.STOPPED

        except Exception as e:
            workflow.status = OrchestratorStatus.ERROR
            raise

        finally:
            self.correlation_tracker.clear_current()
            workflow.updated_at = asyncio.get_event_loop().time()

        return workflow

    async def _execute_sequential(
        self,
        workflow: WorkflowState,
        tasks: list[dict[str, Any]],
        correlation_context: Any,
    ) -> None:
        """Execute tasks sequentially in order."""
        for idx, task in enumerate(tasks):
            workflow.current_step = idx
            result = await self._execute_task(task, workflow.context, correlation_context)
            workflow.results[task.get("task_id", f"task_{idx}")] = result
            workflow.context["last_result"] = result.output

            if not result.success:
                break

            workflow.updated_at = asyncio.get_event_loop().time()

    async def _execute_concurrent(
        self,
        workflow: WorkflowState,
        tasks: list[dict[str, Any]],
        correlation_context: Any,
    ) -> None:
        """Execute tasks concurrently."""

        async def run_task(idx: int, task: dict[str, Any]) -> None:
            result = await self._execute_task(task, workflow.context, correlation_context)
            workflow.results[task.get("task_id", f"task_{idx}")] = result
            workflow.updated_at = asyncio.get_event_loop().time()

        await asyncio.gather(*[run_task(idx, task) for idx, task in enumerate(tasks)])

    async def _execute_handoff(
        self,
        workflow: WorkflowState,
        tasks: list[dict[str, Any]],
        correlation_context: Any,
    ) -> None:
        """Execute with dynamic handoff between agents."""
        current_task = tasks[0] if tasks else None
        idx = 0

        while current_task and idx < len(tasks):
            workflow.current_step = idx
            result = await self._execute_task(current_task, workflow.context, correlation_context)
            workflow.results[current_task.get("task_id", f"task_{idx}")] = result

            if not result.success or not result.output:
                break

            next_agent = result.output.get("next_agent")
            if next_agent:
                for next_task in tasks[idx + 1 :]:
                    if next_task.get("agent_id") == next_agent:
                        current_task = next_task
                        idx = tasks.index(next_task)
                        break
                else:
                    break
            else:
                idx += 1
                current_task = tasks[idx] if idx < len(tasks) else None

            workflow.updated_at = asyncio.get_event_loop().time()

    async def _execute_group_chat(
        self,
        workflow: WorkflowState,
        tasks: list[dict[str, Any]],
        correlation_context: Any,
    ) -> None:
        """Execute with group chat coordination."""
        chat_history = []

        for idx, task in enumerate(tasks):
            workflow.current_step = idx
            workflow.context["chat_history"] = chat_history

            result = await self._execute_task(task, workflow.context, correlation_context)
            workflow.results[task.get("task_id", f"task_{idx}")] = result

            if result.output:
                chat_history.append(
                    {
                        "agent_id": task.get("agent_id"),
                        "message": result.output.get("message", ""),
                        "timestamp": asyncio.get_event_loop().time(),
                    }
                )

            workflow.updated_at = asyncio.get_event_loop().time()

    async def _execute_magentic(
        self,
        workflow: WorkflowState,
        tasks: list[dict[str, Any]],
        correlation_context: Any,
    ) -> None:
        """Execute with magentic plan-build-execute pattern."""
        plan = []

        for idx, task in enumerate(tasks):
            planning_result = await self._plan_task(task, workflow.context, correlation_context)
            if planning_result:
                plan.extend(planning_result)

        for idx, subtask in enumerate(plan):
            workflow.current_step = idx
            result = await self._execute_task(subtask, workflow.context, correlation_context)
            workflow.results[subtask.get("task_id", f"subtask_{idx}")] = result

            if result.output:
                workflow.context["plan_progress"] = (idx + 1) / len(plan)

            workflow.updated_at = asyncio.get_event_loop().time()

    async def _plan_task(
        self,
        task: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Any,
    ) -> Optional[list[dict[str, Any]]]:
        """Plan task decomposition for magentic pattern."""
        agent_id = task.get("agent_id")
        if not agent_id or agent_id not in self._agents:
            return None

        agent = self._agents[agent_id]
        return await agent.plan_task(task.get("input", {}), context)

    async def _execute_task(
        self,
        task: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Any,
    ) -> TaskResult:
        """Execute single task with retry and timeout."""
        task_id = task.get("task_id", f"task_{asyncio.get_event_loop().time()}")
        agent_id = task.get("agent_id")
        input_data = task.get("input", {})

        if not agent_id or agent_id not in self._agents:
            return TaskResult(
                task_id=task_id,
                agent_id=agent_id or "unknown",
                success=False,
                error=f"Agent '{agent_id}' not found",
            )

        agent = self._agents[agent_id]

        if self.config.enable_policy_enforcement:
            policy_result = await self.policy_engine.evaluate_task(task, context)
            if not policy_result.allowed:
                return TaskResult(
                    task_id=task_id,
                    agent_id=agent_id,
                    success=False,
                    error=f"Policy blocked: {policy_result.reason}",
                )

        async with self._task_semaphore:
            for attempt in range(self.config.max_retries):
                try:
                    async with asyncio.timeout(self.config.task_timeout_seconds):
                        child_context = self.correlation_tracker.continue_correlation(
                            baggage={"task_id": task_id, "attempt": str(attempt + 1)}
                        )

                        output = await agent.execute(
                            input_data=input_data,
                            context=context,
                            correlation_context=child_context,
                        )

                        return TaskResult(
                            task_id=task_id,
                            agent_id=agent_id,
                            success=True,
                            output=output,
                            retry_count=attempt,
                        )

                except asyncio.TimeoutError:
                    if attempt == self.config.max_retries - 1:
                        return TaskResult(
                            task_id=task_id,
                            agent_id=agent_id,
                            success=False,
                            error="Task timeout",
                            retry_count=attempt,
                        )

                except Exception as e:
                    if attempt == self.config.max_retries - 1:
                        return TaskResult(
                            task_id=task_id,
                            agent_id=agent_id,
                            success=False,
                            error=str(e),
                            retry_count=attempt,
                        )

                await asyncio.sleep(0.1 * (2**attempt))

        return TaskResult(
            task_id=task_id,
            agent_id=agent_id,
            success=False,
            error="Max retries exceeded",
            retry_count=self.config.max_retries,
        )

    async def _emit_event(
        self,
        event_type: EventType,
        severity: Severity,
        title: str,
        payload: dict[str, Any],
        description: Optional[str] = None,
    ) -> str:
        """
        Emit security event.

        Args:
            event_type: Event type
            severity: Event severity
            title: Event title
            payload: Event payload
            description: Optional description

        Returns:
            Event ID
        """
        event = SecurityEvent.create(
            event_type=event_type,
            severity=severity,
            title=title,
            description=description or title,
            source_agent=self.config.orchestrator_id,
            payload=payload,
        )

        return await self.event_bus.publish(event)

    @property
    def status(self) -> OrchestratorStatus:
        """Get orchestrator status."""
        return self._status

    @property
    def is_running(self) -> bool:
        """Check if orchestrator is running."""
        return self._status == OrchestratorStatus.RUNNING

    def get_workflow(self, workflow_id: str) -> Optional[WorkflowState]:
        """
        Get workflow state by ID.

        Args:
            workflow_id: Workflow identifier

        Returns:
            Workflow state or None
        """
        return self._workflows.get(workflow_id)

    async def pause(self) -> None:
        """Pause orchestrator execution."""
        if self._status == OrchestratorStatus.RUNNING:
            self._status = OrchestratorStatus.PAUSED

    async def resume(self) -> None:
        """Resume orchestrator execution."""
        if self._status == OrchestratorStatus.PAUSED:
            self._status = OrchestratorStatus.RUNNING
