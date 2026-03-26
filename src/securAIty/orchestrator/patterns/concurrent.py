"""
Concurrent Pattern Implementation

Parallel workflow execution where multiple tasks run simultaneously
with result aggregation and synchronization support.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ...agents.base import BaseAgent
from ...events.correlation import CorrelationContext


@dataclass
class ConcurrentTask:
    """
    Task for concurrent execution.

    Attributes:
        task_id: Unique task identifier
        agent_id: Executing agent ID
        input_data: Task input data
        timeout: Task timeout in seconds
        required: Whether task is required for success
        weight: Result aggregation weight
    """

    task_id: str
    agent_id: str
    input_data: dict[str, Any] = field(default_factory=dict)
    timeout: float = 300.0
    required: bool = True
    weight: float = 1.0


@dataclass
class TaskResult:
    """
    Result from concurrent task execution.

    Attributes:
        task_id: Task identifier
        agent_id: Executing agent ID
        success: Whether task succeeded
        output: Task output
        error: Error message if failed
        duration: Execution duration
    """

    task_id: str
    agent_id: str
    success: bool
    output: Any = None
    error: Optional[str] = None
    duration: float = 0.0


class ConcurrentExecutor:
    """
    Concurrent workflow executor.

    Executes multiple tasks in parallel with configurable
    concurrency limits, timeout handling, and result aggregation.

    Attributes:
        max_concurrency: Maximum parallel tasks
        aggregation_strategy: Result aggregation method
    """

    def __init__(
        self,
        max_concurrency: int = 10,
        aggregation_strategy: str = "all",
    ) -> None:
        """
        Initialize concurrent executor.

        Args:
            max_concurrency: Maximum parallel tasks
            aggregation_strategy: Strategy for aggregating results
        """
        self._tasks: list[ConcurrentTask] = []
        self._agents: dict[str, BaseAgent] = {}
        self._max_concurrency = max_concurrency
        self._aggregation_strategy = aggregation_strategy
        self._semaphore: Optional[asyncio.Semaphore] = None

    def add_task(
        self,
        task_id: str,
        agent_id: str,
        input_data: Optional[dict[str, Any]] = None,
        timeout: float = 300.0,
        required: bool = True,
        weight: float = 1.0,
    ) -> "ConcurrentExecutor":
        """
        Add task for concurrent execution.

        Args:
            task_id: Task identifier
            agent_id: Agent to execute
            input_data: Task input
            timeout: Task timeout
            required: Whether task is required
            weight: Aggregation weight

        Returns:
            Self for chaining
        """
        self._tasks.append(
            ConcurrentTask(
                task_id=task_id,
                agent_id=agent_id,
                input_data=input_data or {},
                timeout=timeout,
                required=required,
                weight=weight,
            )
        )
        return self

    def register_agent(self, agent: BaseAgent) -> None:
        """
        Register agent for execution.

        Args:
            agent: Agent instance
        """
        self._agents[agent.agent_id] = agent

    async def execute(
        self,
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext] = None,
    ) -> dict[str, Any]:
        """
        Execute all tasks concurrently.

        Args:
            context: Shared context
            correlation_context: Correlation tracking

        Returns:
            Context with aggregated results

        Raises:
            RuntimeError: If required tasks fail
        """
        self._semaphore = asyncio.Semaphore(self._max_concurrency)

        tasks_to_run = []

        for task in self._tasks:
            if task.agent_id not in self._agents:
                if task.required:
                    raise RuntimeError(f"Required agent '{task.agent_id}' not registered")
                continue

            tasks_to_run.append(self._execute_task(task, context, correlation_context))

        results = await asyncio.gather(*tasks_to_run, return_exceptions=True)

        aggregated = self._aggregate_results(results)

        context["concurrent_results"] = aggregated
        context["success_count"] = sum(1 for r in aggregated.values() if r.get("success", False))
        context["failure_count"] = len(aggregated) - context["success_count"]

        required_failures = [
            task_id
            for task_id, result in aggregated.items()
            if not result.get("success", False)
            and next((t for t in self._tasks if t.task_id == task_id), {}).get("required", True)
        ]

        if required_failures:
            raise RuntimeError(f"Required tasks failed: {required_failures}")

        return context

    async def _execute_task(
        self,
        task: ConcurrentTask,
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> TaskResult:
        """
        Execute single task with semaphore and timeout.

        Args:
            task: Task to execute
            context: Shared context
            correlation_context: Correlation tracking

        Returns:
            Task result
        """
        async with self._semaphore:
            start_time = asyncio.get_event_loop().time()

            try:
                agent = self._agents[task.agent_id]

                async with asyncio.timeout(task.timeout):
                    output = await agent.execute(
                        input_data=task.input_data,
                        context=context,
                        correlation_context=correlation_context,
                    )

                duration = asyncio.get_event_loop().time() - start_time

                return TaskResult(
                    task_id=task.task_id,
                    agent_id=task.agent_id,
                    success=True,
                    output=output,
                    duration=duration,
                )

            except asyncio.TimeoutError as e:
                duration = asyncio.get_event_loop().time() - start_time
                return TaskResult(
                    task_id=task.task_id,
                    agent_id=task.agent_id,
                    success=False,
                    error=f"Task timeout after {task.timeout}s",
                    duration=duration,
                )

            except Exception as e:
                duration = asyncio.get_event_loop().time() - start_time
                return TaskResult(
                    task_id=task.task_id,
                    agent_id=task.agent_id,
                    success=False,
                    error=str(e),
                    duration=duration,
                )

    def _aggregate_results(
        self,
        results: list[TaskResult | Exception],
    ) -> dict[str, dict[str, Any]]:
        """
        Aggregate task results.

        Args:
            results: List of task results

        Returns:
            Aggregated results by task ID
        """
        aggregated = {}

        for result in results:
            if isinstance(result, Exception):
                aggregated[f"error_{id(result)}"] = {
                    "success": False,
                    "error": str(result),
                }
                continue

            aggregated[result.task_id] = {
                "success": result.success,
                "output": result.output,
                "agent_id": result.agent_id,
                "error": result.error,
                "duration": result.duration,
            }

        if self._aggregation_strategy == "all":
            pass

        elif self._aggregation_strategy == "any":
            pass

        elif self._aggregation_strategy == "majority":
            success_count = sum(1 for r in aggregated.values() if r.get("success", False))
            aggregated["_majority_success"] = success_count > len(aggregated) / 2

        elif self._aggregation_strategy == "weighted":
            weighted_sum = 0.0
            total_weight = 0.0

            for result in aggregated.values():
                if result.get("success", False) and result.get("output"):
                    task = next((t for t in self._tasks if t.task_id == result.get("task_id")), None)
                    weight = task.weight if task else 1.0

                    if isinstance(result["output"], (int, float)):
                        weighted_sum += result["output"] * weight
                        total_weight += weight

            if total_weight > 0:
                aggregated["_weighted_average"] = weighted_sum / total_weight

        return aggregated

    def set_aggregation_strategy(self, strategy: str) -> None:
        """
        Set result aggregation strategy.

        Args:
            strategy: Strategy name (all, any, majority, weighted)
        """
        self._aggregation_strategy = strategy

    @property
    def task_count(self) -> int:
        """Get number of tasks."""
        return len(self._tasks)

    def clear_tasks(self) -> None:
        """Clear all tasks."""
        self._tasks.clear()


class ResultAggregator:
    """
    Configurable result aggregator for concurrent execution.

    Provides various aggregation strategies for combining
    multiple task outputs into a single result.
    """

    def __init__(self, strategy: str = "collect") -> None:
        """
        Initialize aggregator.

        Args:
            strategy: Aggregation strategy
        """
        self._strategy = strategy
        self._custom_func: Optional[Callable] = None

    def aggregate(self, results: list[TaskResult]) -> Any:
        """
        Aggregate results using configured strategy.

        Args:
            results: List of task results

        Returns:
            Aggregated result
        """
        if self._strategy == "collect":
            return [r.output for r in results if r.success]

        elif self._strategy == "first":
            for r in results:
                if r.success:
                    return r.output
            return None

        elif self._strategy == "merge":
            merged = {}
            for r in results:
                if r.success and isinstance(r.output, dict):
                    merged.update(r.output)
            return merged

        elif self._strategy == "concat":
            concatenated = []
            for r in results:
                if r.success:
                    if isinstance(r.output, list):
                        concatenated.extend(r.output)
                    else:
                        concatenated.append(r.output)
            return concatenated

        elif self._strategy == "custom" and self._custom_func:
            return self._custom_func(results)

        return results

    def with_custom(
        self,
        func: Callable[[list[TaskResult]], Any],
    ) -> "ResultAggregator":
        """
        Set custom aggregation function.

        Args:
            func: Aggregation function

        Returns:
            Self for chaining
        """
        self._custom_func = func
        self._strategy = "custom"
        return self
