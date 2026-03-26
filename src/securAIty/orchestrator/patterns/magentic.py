"""
Magentic Pattern Implementation

Plan-build-execute coordination where a manager agent dynamically
assigns tasks to worker agents and aggregates results.
"""

import asyncio
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from ...agents.base import BaseAgent
from ...events.correlation import CorrelationContext


class TaskStatus(Enum):
    """Task execution status."""

    PENDING = auto()
    PLANNED = auto()
    ASSIGNED = auto()
    IN_PROGRESS = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass
class SubTask:
    """
    Subtask in magentic workflow.

    Attributes:
        task_id: Unique task identifier
        description: Task description
        agent_id: Assigned agent ID
        input_data: Task input data
        status: Current task status
        output: Task output if completed
        error: Error message if failed
        dependencies: Dependent task IDs
        priority: Task priority
    """

    task_id: str
    description: str
    agent_id: Optional[str] = None
    input_data: dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    output: Any = None
    error: Optional[str] = None
    dependencies: list[str] = field(default_factory=list)
    priority: int = 100


@dataclass
class Plan:
    """
    Execution plan for magentic workflow.

    Attributes:
        plan_id: Unique plan identifier
        goal: Overall goal description
        tasks: Ordered list of subtasks
        created_at: Plan creation time
        metadata: Additional plan metadata
    """

    plan_id: str
    goal: str
    tasks: list[SubTask] = field(default_factory=list)
    created_at: float = field(default_factory=lambda: asyncio.get_event_loop().time())
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_task(self, task: SubTask) -> "Plan":
        """Add task to plan."""
        self.tasks.append(task)
        self.tasks.sort(key=lambda t: t.priority)
        return self

    def get_ready_tasks(self) -> list[SubTask]:
        """Get tasks ready to execute (dependencies met)."""
        completed = {t.task_id for t in self.tasks if t.status == TaskStatus.COMPLETED}

        ready = []
        for task in self.tasks:
            if task.status == TaskStatus.PENDING:
                if all(dep in completed for dep in task.dependencies):
                    ready.append(task)

        return ready

    def get_completed_tasks(self) -> list[SubTask]:
        """Get completed tasks."""
        return [t for t in self.tasks if t.status == TaskStatus.COMPLETED]

    def get_failed_tasks(self) -> list[SubTask]:
        """Get failed tasks."""
        return [t for t in self.tasks if t.status == TaskStatus.FAILED]

    def is_complete(self) -> bool:
        """Check if all tasks are completed or failed."""
        return all(t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED) for t in self.tasks)

    def success_rate(self) -> float:
        """Calculate task success rate."""
        if not self.tasks:
            return 0.0

        completed = sum(1 for t in self.tasks if t.status == TaskStatus.COMPLETED)
        return completed / len(self.tasks)


class MagenticManager:
    """
    Magentic pattern manager for plan-build-execute workflows.

    Coordinates planning, task assignment, execution, and result
    aggregation with dynamic replanning capabilities.

    Attributes:
        manager_agent: Planning/manager agent
        max_replans: Maximum replanning attempts
        parallel_execution: Enable parallel task execution
    """

    def __init__(
        self,
        manager_agent: BaseAgent,
        max_replans: int = 3,
        parallel_execution: bool = True,
    ) -> None:
        """
        Initialize magentic manager.

        Args:
            manager_agent: Manager/planner agent
            max_replans: Maximum replanning attempts
            parallel_execution: Enable parallel execution
        """
        self._manager = manager_agent
        self._max_replans = max_replans
        self._parallel_execution = parallel_execution

        self._workers: dict[str, BaseAgent] = {}
        self._current_plan: Optional[Plan] = None
        self._replan_count = 0
        self._context: dict[str, Any] = {}

    def register_worker(self, agent: BaseAgent) -> "MagenticManager":
        """
        Register worker agent.

        Args:
            agent: Worker agent to register

        Returns:
            Self for chaining
        """
        self._workers[agent.agent_id] = agent
        return self

    async def execute(
        self,
        goal: str,
        initial_context: dict[str, Any],
        correlation_context: Optional[CorrelationContext] = None,
    ) -> dict[str, Any]:
        """
        Execute magentic workflow.

        Args:
            goal: Overall goal to achieve
            initial_context: Initial context
            correlation_context: Correlation tracking

        Returns:
            Final result with plan and outputs

        Raises:
            RuntimeError: If planning fails or max replans exceeded
        """
        self._context = dict(initial_context)
        self._replan_count = 0

        while self._replan_count <= self._max_replans:
            plan = await self._create_plan(goal, self._context, correlation_context)

            if not plan or not plan.tasks:
                raise RuntimeError("Failed to create plan")

            self._current_plan = plan

            await self._execute_plan(plan, correlation_context)

            if self._current_plan.success_rate() >= 0.8:
                break

            if self._replan_count < self._max_replans:
                await self._replan(goal, self._context, correlation_context)

            self._replan_count += 1

        return self._aggregate_results()

    async def _create_plan(
        self,
        goal: str,
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> Plan:
        """
        Create execution plan using manager agent.

        Args:
            goal: Overall goal
            context: Current context
            correlation_context: Correlation tracking

        Returns:
            Execution plan
        """
        import uuid

        input_data = {
            "goal": goal,
            "context": context,
            "available_workers": list(self._workers.keys()),
            "worker_capabilities": {
                aid: w.capabilities for aid, w in self._workers.items()
            },
        }

        if self._replan_count > 0:
            input_data["previous_failures"] = [
                {"task_id": t.task_id, "error": t.error}
                for t in self._current_plan.get_failed_tasks()
            ] if self._current_plan else []

        output = await self._manager.execute(
            input_data=input_data,
            context=context,
            correlation_context=correlation_context,
        )

        plan_data = self._extract_plan(output)

        plan = Plan(
            plan_id=str(uuid.uuid4()),
            goal=goal,
            metadata=plan_data.get("metadata", {}),
        )

        for task_data in plan_data.get("tasks", []):
            task = SubTask(
                task_id=task_data.get("task_id", str(uuid.uuid4())),
                description=task_data.get("description", ""),
                agent_id=task_data.get("agent_id"),
                input_data=task_data.get("input_data", {}),
                dependencies=task_data.get("dependencies", []),
                priority=task_data.get("priority", 100),
            )
            plan.add_task(task)

        for task in plan.tasks:
            task.status = TaskStatus.PLANNED

        return plan

    async def _execute_plan(
        self,
        plan: Plan,
        correlation_context: Optional[CorrelationContext],
    ) -> None:
        """
        Execute all tasks in plan.

        Args:
            plan: Execution plan
            correlation_context: Correlation tracking
        """
        while not plan.is_complete():
            ready_tasks = plan.get_ready_tasks()

            if not ready_tasks:
                if not plan.is_complete():
                    remaining = [t for t in plan.tasks if t.status == TaskStatus.PENDING]
                    if remaining:
                        for task in remaining:
                            task.status = TaskStatus.FAILED
                            task.error = "Dependencies not met"
                break

            if self._parallel_execution:
                await self._execute_tasks_parallel(ready_tasks, plan, correlation_context)
            else:
                await self._execute_tasks_sequential(ready_tasks, plan, correlation_context)

    async def _execute_tasks_parallel(
        self,
        tasks: list[SubTask],
        plan: Plan,
        correlation_context: Optional[CorrelationContext],
    ) -> None:
        """Execute tasks in parallel."""

        async def execute_task(task: SubTask) -> None:
            task.status = TaskStatus.IN_PROGRESS
            task.status = TaskStatus.ASSIGNED

            if not task.agent_id or task.agent_id not in self._workers:
                task.status = TaskStatus.FAILED
                task.error = f"Worker '{task.agent_id}' not available"
                return

            worker = self._workers[task.agent_id]

            try:
                output = await worker.execute(
                    input_data=task.input_data,
                    context=self._context,
                    correlation_context=correlation_context,
                )

                task.output = output
                task.status = TaskStatus.COMPLETED

                if isinstance(output, dict):
                    self._context[f"task_{task.task_id}_output"] = output

            except Exception as e:
                task.error = str(e)
                task.status = TaskStatus.FAILED

        await asyncio.gather(*[execute_task(task) for task in tasks])

    async def _execute_tasks_sequential(
        self,
        tasks: list[SubTask],
        plan: Plan,
        correlation_context: Optional[CorrelationContext],
    ) -> None:
        """Execute tasks sequentially."""
        for task in tasks:
            task.status = TaskStatus.IN_PROGRESS
            task.status = TaskStatus.ASSIGNED

            if not task.agent_id or task.agent_id not in self._workers:
                task.status = TaskStatus.FAILED
                task.error = f"Worker '{task.agent_id}' not available"
                continue

            worker = self._workers[task.agent_id]

            try:
                output = await worker.execute(
                    input_data=task.input_data,
                    context=self._context,
                    correlation_context=correlation_context,
                )

                task.output = output
                task.status = TaskStatus.COMPLETED

                if isinstance(output, dict):
                    self._context[f"task_{task.task_id}_output"] = output

            except Exception as e:
                task.error = str(e)
                task.status = TaskStatus.FAILED

    async def _replan(
        self,
        goal: str,
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> None:
        """
        Replan based on execution results.

        Args:
            goal: Overall goal
            context: Current context
            correlation_context: Correlation tracking
        """
        failed_tasks = self._current_plan.get_failed_tasks()

        if not failed_tasks:
            return

        replan_input = {
            "goal": goal,
            "completed_tasks": [
                {"task_id": t.task_id, "output": t.output}
                for t in self._current_plan.get_completed_tasks()
            ],
            "failed_tasks": [
                {"task_id": t.task_id, "error": t.error, "description": t.description}
                for t in failed_tasks
            ],
            "remaining_goal": self._identify_remaining_work(goal, context),
        }

        output = await self._manager.execute(
            input_data=replan_input,
            context=context,
            correlation_context=correlation_context,
        )

        replan_data = self._extract_plan(output)

        for task_data in replan_data.get("tasks", []):
            new_task = SubTask(
                task_id=f"replan_{task_data.get('task_id', '')}",
                description=task_data.get("description", ""),
                agent_id=task_data.get("agent_id"),
                input_data=task_data.get("input_data", {}),
                priority=task_data.get("priority", 50),
            )
            self._current_plan.add_task(new_task)

    def _identify_remaining_work(self, goal: str, context: dict[str, Any]) -> str:
        """Identify remaining work to achieve goal."""
        completed = self._current_plan.get_completed_tasks()
        failed = self._current_plan.get_failed_tasks()

        return (
            f"Goal: {goal}. "
            f"Completed: {len(completed)} tasks. "
            f"Failed: {len(failed)} tasks. "
            f"Need to complete remaining work."
        )

    def _extract_plan(self, output: Any) -> dict[str, Any]:
        """Extract plan data from agent output."""
        if isinstance(output, dict):
            return output.get("plan", output)

        return {"tasks": [], "metadata": {}}

    def _aggregate_results(self) -> dict[str, Any]:
        """Aggregate results from plan execution."""
        if not self._current_plan:
            return {"success": False, "error": "No plan executed"}

        return {
            "success": self._current_plan.success_rate() >= 0.5,
            "plan_id": self._current_plan.plan_id,
            "goal": self._current_plan.goal,
            "total_tasks": len(self._current_plan.tasks),
            "completed_tasks": len(self._current_plan.get_completed_tasks()),
            "failed_tasks": len(self._current_plan.get_failed_tasks()),
            "success_rate": self._current_plan.success_rate(),
            "task_outputs": {
                t.task_id: t.output
                for t in self._current_plan.tasks
                if t.status == TaskStatus.COMPLETED
            },
            "task_errors": {
                t.task_id: t.error
                for t in self._current_plan.tasks
                if t.status == TaskStatus.FAILED
            },
            "replan_count": self._replan_count,
            "final_context": self._context,
        }

    def get_current_plan(self) -> Optional[Plan]:
        """Get current execution plan."""
        return self._current_plan

    def get_progress(self) -> dict[str, Any]:
        """Get execution progress."""
        if not self._current_plan:
            return {"progress": 0.0, "status": "not_started"}

        return {
            "progress": self._current_plan.success_rate(),
            "status": "executing" if not self._current_plan.is_complete() else "completed",
            "completed": len(self._current_plan.get_completed_tasks()),
            "failed": len(self._current_plan.get_failed_tasks()),
            "pending": len([t for t in self._current_plan.tasks if t.status == TaskStatus.PENDING]),
            "in_progress": len([t for t in self._current_plan.tasks if t.status == TaskStatus.IN_PROGRESS]),
        }
