"""
Task router module for AI Security Manager.

Handles capability-based routing, agent selection, and load balancing.
"""

from dataclasses import dataclass, field
from typing import Optional
import asyncio
from collections import defaultdict
import random

from ..agents.base import BaseAgent, AgentCapability, TaskPriority, HealthStatus


@dataclass
class AgentScore:
    """
    Score for an agent based on various factors.

    Attributes:
        agent_id: The agent's unique identifier
        capability_match: Score for capability match (0.0 to 1.0)
        load_score: Score based on current load (0.0 to 1.0, higher is better)
        health_score: Score based on health status (0.0 to 1.0)
        latency_score: Score based on historical latency (0.0 to 1.0)
        total_score: Weighted total score
    """

    agent_id: str
    capability_match: float = 0.0
    load_score: float = 0.0
    health_score: float = 0.0
    latency_score: float = 0.0
    total_score: float = 0.0

    def calculate_total(self, weights: Optional[dict[str, float]] = None) -> float:
        """
        Calculate weighted total score.

        Args:
            weights: Optional weights for each score component.
                     Defaults to equal weighting.

        Returns:
            Weighted total score
        """
        if weights is None:
            weights = {
                "capability_match": 0.4,
                "load_score": 0.25,
                "health_score": 0.25,
                "latency_score": 0.1,
            }

        self.total_score = (
            self.capability_match * weights.get("capability_match", 0.25)
            + self.load_score * weights.get("load_score", 0.25)
            + self.health_score * weights.get("health_score", 0.25)
            + self.latency_score * weights.get("latency_score", 0.25)
        )
        return self.total_score


@dataclass
class RoutingDecision:
    """
    Decision made by the task router.

    Attributes:
        selected_agent_id: ID of the selected agent
        fallback_agent_id: ID of fallback agent if primary fails
        score: Score of the selected agent
        all_candidates: List of all candidate agent IDs considered
        routing_reason: Reason for the routing decision
    """

    selected_agent_id: str
    fallback_agent_id: Optional[str] = None
    score: float = 0.0
    all_candidates: list[str] = field(default_factory=list)
    routing_reason: str = ""


class TaskRouter:
    """
    Routes tasks to appropriate agents based on capabilities and load.

    Provides capability-based routing with load balancing, health-aware
    selection, and fallback mechanisms.
    """

    def __init__(
        self,
        load_balancing_strategy: str = "least_loaded",
        enable_fallback: bool = True,
        max_retries: int = 2,
    ) -> None:
        """
        Initialize the task router.

        Args:
            load_balancing_strategy: Strategy for load balancing.
                                     Options: 'least_loaded', 'round_robin', 'random'
            enable_fallback: Whether to enable fallback routing
            max_retries: Maximum number of retry attempts
        """
        self._agent_registry: dict[str, BaseAgent] = {}
        self._capability_index: dict[str, list[str]] = defaultdict(list)
        self._agent_load: dict[str, int] = defaultdict(int)
        self._agent_latency: dict[str, list[float]] = defaultdict(list)
        self._round_robin_counters: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

        self.load_balancing_strategy = load_balancing_strategy
        self.enable_fallback = enable_fallback
        self.max_retries = max_retries

    async def register_agent(self, agent: BaseAgent) -> None:
        """
        Register an agent with the router.

        Args:
            agent: The agent to register
        """
        async with self._lock:
            agent_id = agent.agent_id
            self._agent_registry[agent_id] = agent

            for capability in agent.metadata.capabilities:
                self._capability_index[capability.name].append(agent_id)

            self._agent_load[agent_id] = 0

    async def unregister_agent(self, agent_id: str) -> None:
        """
        Unregister an agent from the router.

        Args:
            agent_id: ID of the agent to unregister
        """
        async with self._lock:
            if agent_id in self._agent_registry:
                del self._agent_registry[agent_id]

            for capability, agents in self._capability_index.items():
                if agent_id in agents:
                    agents.remove(agent_id)

            if agent_id in self._agent_load:
                del self._agent_load[agent_id]

            if agent_id in self._agent_latency:
                del self._agent_latency[agent_id]

    async def route_task(
        self,
        capability: str,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> Optional[RoutingDecision]:
        """
        Route a task to an appropriate agent.

        Args:
            capability: Name of the required capability
            priority: Task priority level

        Returns:
            RoutingDecision with selected agent, or None if no agent available
        """
        async with self._lock:
            candidates = self._capability_index.get(capability, [])

            if not candidates:
                return None

            active_candidates = await self._filter_healthy_agents(candidates)

            if not active_candidates:
                return None

            if priority == TaskPriority.CRITICAL:
                selected = await self._select_by_health_and_load(active_candidates)
            elif self.load_balancing_strategy == "least_loaded":
                selected = await self._select_least_loaded(active_candidates)
            elif self.load_balancing_strategy == "round_robin":
                selected = await self._select_round_robin(capability, active_candidates)
            else:
                selected = await self._select_random(active_candidates)

            if not selected:
                return None

            fallback = None
            if self.enable_fallback and len(active_candidates) > 1:
                fallback_candidates = [
                    aid for aid in active_candidates if aid != selected
                ]
                if fallback_candidates:
                    fallback = random.choice(fallback_candidates)

            score = await self._calculate_agent_score(selected, capability)

            return RoutingDecision(
                selected_agent_id=selected,
                fallback_agent_id=fallback,
                score=score.total_score,
                all_candidates=active_candidates,
                routing_reason=f"Selected using {self.load_balancing_strategy} strategy",
            )

    async def _filter_healthy_agents(
        self,
        agent_ids: list[str],
    ) -> list[str]:
        """Filter to only healthy agents."""
        healthy = []
        for agent_id in agent_ids:
            agent = self._agent_registry.get(agent_id)
            if agent and agent.metadata.health_status in (
                HealthStatus.HEALTHY,
                HealthStatus.DEGRADED,
            ):
                healthy.append(agent_id)
        return healthy

    async def _select_least_loaded(
        self,
        candidates: list[str],
    ) -> Optional[str]:
        """Select the agent with the lowest current load."""
        if not candidates:
            return None

        min_load = float("inf")
        selected = None

        for agent_id in candidates:
            load = self._agent_load.get(agent_id, 0)
            if load < min_load:
                min_load = load
                selected = agent_id

        return selected

    async def _select_round_robin(
        self,
        capability: str,
        candidates: list[str],
    ) -> Optional[str]:
        """Select agent using round-robin strategy."""
        if not candidates:
            return None

        sorted_candidates = sorted(candidates)
        counter = self._round_robin_counters[capability]
        selected_idx = counter % len(sorted_candidates)
        self._round_robin_counters[capability] = counter + 1

        return sorted_candidates[selected_idx]

    async def _select_random(self, candidates: list[str]) -> Optional[str]:
        """Select a random agent from candidates."""
        if not candidates:
            return None
        return random.choice(candidates)

    async def _select_by_health_and_load(
        self,
        candidates: list[str],
    ) -> Optional[str]:
        """Select agent based on health and load for critical tasks."""
        if not candidates:
            return None

        best_score = 0.0
        selected = None

        for agent_id in candidates:
            score = await self._calculate_agent_score(agent_id, "")
            if score.total_score > best_score:
                best_score = score.total_score
                selected = agent_id

        return selected

    async def _calculate_agent_score(
        self,
        agent_id: str,
        capability: str,
    ) -> AgentScore:
        """Calculate comprehensive score for an agent."""
        agent = self._agent_registry.get(agent_id)
        if not agent:
            return AgentScore(agent_id=agent_id)

        score = AgentScore(agent_id=agent_id)

        has_capability = capability in [
            cap.name for cap in agent.metadata.capabilities
        ]
        score.capability_match = 1.0 if has_capability else 0.0

        health_status = agent.metadata.health_status
        health_scores = {
            HealthStatus.HEALTHY: 1.0,
            HealthStatus.DEGRADED: 0.5,
            HealthStatus.UNHEALTHY: 0.0,
            HealthStatus.UNKNOWN: 0.3,
        }
        score.health_score = health_scores.get(health_status, 0.0)

        current_load = self._agent_load.get(agent_id, 0)
        max_expected_load = 100
        score.load_score = max(0.0, 1.0 - (current_load / max_expected_load))

        latencies = self._agent_latency.get(agent_id, [])
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            max_latency = 5000
            score.latency_score = max(0.0, 1.0 - (avg_latency / max_latency))
        else:
            score.latency_score = 0.8

        score.calculate_total()
        return score

    async def record_task_completion(
        self,
        agent_id: str,
        execution_time_ms: float,
        success: bool,
    ) -> None:
        """
        Record task completion for load tracking.

        Args:
            agent_id: ID of the agent that completed the task
            execution_time_ms: Execution time in milliseconds
            success: Whether the task succeeded
        """
        async with self._lock:
            if agent_id in self._agent_load:
                self._agent_load[agent_id] = max(0, self._agent_load[agent_id] - 1)

            self._agent_latency[agent_id].append(execution_time_ms)

            latency_history = self._agent_latency[agent_id]
            if len(latency_history) > 100:
                self._agent_latency[agent_id] = latency_history[-100:]

    async def record_task_start(self, agent_id: str) -> None:
        """
        Record task start for load tracking.

        Args:
            agent_id: ID of the agent starting the task
        """
        async with self._lock:
            if agent_id in self._agent_load:
                self._agent_load[agent_id] += 1

    def get_registered_agents(self) -> list[str]:
        """Get list of registered agent IDs."""
        return list(self._agent_registry.keys())

    def get_agents_for_capability(self, capability: str) -> list[str]:
        """Get all agents that provide a specific capability."""
        return self._capability_index.get(capability, []).copy()

    async def get_routing_stats(self) -> dict:
        """Get routing statistics."""
        async with self._lock:
            return {
                "total_agents": len(self._agent_registry),
                "total_capabilities": len(self._capability_index),
                "load_distribution": dict(self._agent_load),
                "capability_distribution": {
                    cap: len(agents) for cap, agents in self._capability_index.items()
                },
            }
