"""
Handoff Pattern Implementation

Dynamic task handoff between specialist agents where each agent
decides when to transfer control to another agent.
"""

import ast
import operator
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from ...agents.base import BaseAgent
from ...events.correlation import CorrelationContext


SAFE_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.And: operator.and_,
    ast.Or: operator.or_,
    ast.In: lambda x, y: x in y,
    ast.NotIn: lambda x, y: x not in y,
    ast.Is: lambda x, y: x is y,
    ast.IsNot: lambda x, y: x is not y,
}


def _safe_eval_condition(condition: str, context: dict[str, Any]) -> bool:
    try:
        tree = ast.parse(condition, mode="eval")
        return _eval_node(tree.body, context)
    except Exception:
        return True


def _eval_node(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, context)
        for op, comparator in zip(node.ops, node.comparators):
            right = _eval_node(comparator, context)
            op_func = SAFE_OPERATORS.get(type(op))
            if not op_func:
                raise ValueError(f"Unsafe operator: {type(op)}")
            if not op_func(left, right):
                return False
        return True
    elif isinstance(node, ast.BoolOp):
        op_func = SAFE_OPERATORS.get(type(node.op))
        if not op_func:
            raise ValueError(f"Unsafe boolean operator: {type(node.op)}")
        values = [_eval_node(v, context) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        elif isinstance(node.op, ast.Or):
            return any(values)
        return False
    elif isinstance(node, ast.Name):
        if node.id == "True":
            return True
        elif node.id == "False":
            return False
        elif node.id == "None":
            return None
        if node.id not in context:
            raise ValueError(f"Undefined variable: {node.id}")
        return context[node.id]
    elif isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.Str):
        return node.s
    elif isinstance(node, ast.NameConstant):
        return node.value
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_node(node.operand, context)
    elif isinstance(node, ast.Subscript):
        value = _eval_node(node.value, context)
        slice_key = _eval_node(node.slice, context)
        return value[slice_key]
    elif isinstance(node, ast.Index):
        return _eval_node(node.value, context)
    elif isinstance(node, ast.Attribute):
        value = _eval_node(node.value, context)
        if isinstance(value, dict):
            return value.get(node.attr)
        raise ValueError("Attribute access not allowed")
    raise ValueError(f"Unsupported node type: {type(node)}")


class HandoffDecision(Enum):
    """Handoff decision types."""

    CONTINUE = auto()
    HANDOFF = auto()
    COMPLETE = auto()
    ESCALATE = auto()


@dataclass
class HandoffTarget:
    """
    Target agent for handoff.

    Attributes:
        agent_id: Target agent identifier
        condition: Condition for selecting this target
        priority: Selection priority (lower = higher)
        context_transform: Optional context transformation
    """

    agent_id: str
    condition: Optional[str] = None
    priority: int = 100
    context_transform: Optional[dict[str, str]] = None


@dataclass
class HandoffResult:
    """
    Result of handoff decision.

    Attributes:
        decision: Handoff decision type
        target_agent: Target agent ID if handing off
        reason: Decision reasoning
        context_updates: Context updates to apply
        output: Optional output if completing
    """

    decision: HandoffDecision
    target_agent: Optional[str] = None
    reason: str = ""
    context_updates: dict[str, Any] = field(default_factory=dict)
    output: Any = None


class HandoffAgent:
    """
    Wrapper for agents participating in handoff pattern.

    Extends agent with handoff capabilities including
    target selection and decision logic.

    Attributes:
        agent: Wrapped agent instance
        handoff_targets: Possible handoff targets
        max_iterations: Maximum handoffs before escalation
    """

    def __init__(
        self,
        agent: BaseAgent,
        handoff_targets: Optional[list[HandoffTarget]] = None,
        max_iterations: int = 10,
    ) -> None:
        """
        Initialize handoff agent.

        Args:
            agent: Agent to wrap
            handoff_targets: Possible handoff targets
            max_iterations: Maximum handoffs
        """
        self._agent = agent
        self._handoff_targets = handoff_targets or []
        self._max_iterations = max_iterations

    @property
    def agent_id(self) -> str:
        """Get agent identifier."""
        return self._agent.agent_id

    @property
    def agent(self) -> BaseAgent:
        """Get wrapped agent."""
        return self._agent

    def add_handoff_target(
        self,
        agent_id: str,
        condition: Optional[str] = None,
        priority: int = 100,
    ) -> "HandoffAgent":
        """
        Add handoff target.

        Args:
            agent_id: Target agent ID
            condition: Selection condition
            priority: Selection priority

        Returns:
            Self for chaining
        """
        self._handoff_targets.append(
            HandoffTarget(
                agent_id=agent_id,
                condition=condition,
                priority=priority,
            )
        )
        self._handoff_targets.sort(key=lambda t: t.priority)
        return self

    async def execute_with_handoff(
        self,
        input_data: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext] = None,
    ) -> HandoffResult:
        """
        Execute agent and determine handoff decision.

        Args:
            input_data: Agent input
            context: Shared context
            correlation_context: Correlation tracking

        Returns:
            Handoff result with decision
        """
        output = await self._agent.execute(
            input_data=input_data,
            context=context,
            correlation_context=correlation_context,
        )

        handoff_info = self._extract_handoff_info(output)

        if handoff_info.get("complete"):
            return HandoffResult(
                decision=HandoffDecision.COMPLETE,
                reason=handoff_info.get("reason", "Task completed"),
                output=output,
            )

        if handoff_info.get("escalate"):
            return HandoffResult(
                decision=HandoffDecision.ESCALATE,
                reason=handoff_info.get("reason", "Escalation required"),
                context_updates=handoff_info.get("context_updates", {}),
            )

        target_agent = handoff_info.get("next_agent")

        if target_agent:
            return HandoffResult(
                decision=HandoffDecision.HANDOFF,
                target_agent=target_agent,
                reason=handoff_info.get("reason", "Handoff to specialist"),
                context_updates=handoff_info.get("context_updates", {}),
            )

        selected_target = self._select_handoff_target(context, output)

        if selected_target:
            return HandoffResult(
                decision=HandoffDecision.HANDOFF,
                target_agent=selected_target.agent_id,
                reason=f"Selected based on {selected_target.condition or 'priority'}",
                context_updates=self._transform_context(selected_target, context, output),
            )

        return HandoffResult(
            decision=HandoffDecision.CONTINUE,
            reason="No handoff needed",
        )

    def _extract_handoff_info(self, output: Any) -> dict[str, Any]:
        """
        Extract handoff information from output.

        Args:
            output: Agent output

        Returns:
            Handoff information dictionary
        """
        if isinstance(output, dict):
            return {
                "next_agent": output.get("next_agent"),
                "complete": output.get("complete", False),
                "escalate": output.get("escalate", False),
                "reason": output.get("handoff_reason", ""),
                "context_updates": output.get("context_updates", {}),
            }

        return {}

    def _select_handoff_target(
        self,
        context: dict[str, Any],
        output: Any,
    ) -> Optional[HandoffTarget]:
        """
        Select handoff target based on conditions.

        Args:
            context: Current context
            output: Agent output

        Returns:
            Selected target or None
        """
        for target in self._handoff_targets:
            if target.condition is None:
                return target

            if self._evaluate_condition(target.condition, context, output):
                return target

        return None

    def _transform_context(
        self,
        target: HandoffTarget,
        context: dict[str, Any],
        output: Any,
    ) -> dict[str, Any]:
        """
        Transform context for handoff target.

        Args:
            target: Handoff target
            context: Current context
            output: Agent output

        Returns:
            Transformed context
        """
        if not target.context_transform:
            return {}

        transformed = {}

        for new_key, source_key in target.context_transform.items():
            value = self._get_nested_value(context, source_key)
            if value is not None:
                transformed[new_key] = value

        return transformed

    def _evaluate_condition(
        self,
        condition: str,
        context: dict[str, Any],
        output: Any,
    ) -> bool:
        safe_context = {
            "context": context,
            "output": output,
        }
        return _safe_eval_condition(condition, safe_context)

    def _get_nested_value(self, obj: Any, path: str) -> Any:
        """Get nested value using dot notation."""
        parts = path.split(".")
        current = obj

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
            if current is None:
                return None

        return current


class HandoffOrchestrator:
    """
    Orchestrator for handoff pattern execution.

    Manages dynamic handoff between agents until completion,
    with loop detection and escalation support.

    Attributes:
        agents: Registered handoff agents
        max_handoffs: Maximum handoffs before escalation
    """

    def __init__(self, max_handoffs: int = 10) -> None:
        """
        Initialize handoff orchestrator.

        Args:
            max_handoffs: Maximum handoffs allowed
        """
        self._agents: dict[str, HandoffAgent] = {}
        self._max_handoffs = max_handoffs

    def register_agent(self, agent: BaseAgent, **kwargs) -> "HandoffOrchestrator":
        """
        Register agent for handoff.

        Args:
            agent: Agent to register
            **kwargs: Handoff configuration

        Returns:
            Self for chaining
        """
        handoff_agent = HandoffAgent(agent, max_iterations=self._max_handoffs)

        targets = kwargs.get("handoff_targets", [])
        for target in targets:
            handoff_agent.add_handoff_target(**target)

        self._agents[agent.agent_id] = handoff_agent
        return self

    async def execute(
        self,
        start_agent_id: str,
        initial_input: dict[str, Any],
        initial_context: dict[str, Any],
        correlation_context: Optional[CorrelationContext] = None,
    ) -> dict[str, Any]:
        """
        Execute handoff workflow.

        Args:
            start_agent_id: Starting agent ID
            initial_input: Initial input data
            initial_context: Initial context
            correlation_context: Correlation tracking

        Returns:
            Final output and context

        Raises:
            RuntimeError: If agent not found or max handoffs exceeded
        """
        if start_agent_id not in self._agents:
            raise RuntimeError(f"Agent '{start_agent_id}' not registered")

        context = dict(initial_context)
        current_input = dict(initial_input)
        current_agent_id = start_agent_id

        handoff_count = 0
        visited_agents = []
        handoff_history = []

        while handoff_count < self._max_handoffs:
            if current_agent_id not in self._agents:
                raise RuntimeError(f"Agent '{current_agent_id}' not registered")

            if current_agent_id in visited_agents:
                raise RuntimeError(f"Handoff loop detected: {current_agent_id}")

            visited_agents.append(current_agent_id)

            handoff_agent = self._agents[current_agent_id]

            result = await handoff_agent.execute_with_handoff(
                input_data=current_input,
                context=context,
                correlation_context=correlation_context,
            )

            handoff_history.append({
                "agent_id": current_agent_id,
                "decision": result.decision.name,
                "reason": result.reason,
            })

            context.update(result.context_updates)

            if result.decision == HandoffDecision.COMPLETE:
                context["handoff_complete"] = True
                context["handoff_history"] = handoff_history
                context["final_output"] = result.output
                return context

            if result.decision == HandoffDecision.ESCALATE:
                context["handoff_escalated"] = True
                context["handoff_history"] = handoff_history
                context["escalation_reason"] = result.reason
                return context

            if result.decision == HandoffDecision.HANDOFF:
                current_agent_id = result.target_agent
                current_input = context.get("last_output", {})
                handoff_count += 1

            elif result.decision == HandoffDecision.CONTINUE:
                break

        context["handoff_complete"] = True
        context["handoff_history"] = handoff_history
        context["handoff_count"] = handoff_count

        return context

    def get_handoff_chain(self, start_agent_id: str) -> list[str]:
        """
        Get potential handoff chain from start agent.

        Args:
            start_agent_id: Starting agent ID

        Returns:
            List of agent IDs in potential chain
        """
        if start_agent_id not in self._agents:
            return []

        chain = []
        current_id = start_agent_id
        visited = set()

        while current_id and current_id not in visited:
            visited.add(current_id)
            chain.append(current_id)

            agent = self._agents.get(current_id)
            if not agent:
                break

            targets = agent._handoff_targets
            current_id = targets[0].agent_id if targets else None

        return chain
