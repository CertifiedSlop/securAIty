"""
Sequential Pattern Implementation

Linear workflow execution where tasks run one after another
in deterministic order with output passing between steps.
"""

import ast
import asyncio
import operator
from dataclasses import dataclass, field
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


@dataclass
class SequentialStep:
    """
    Single step in sequential workflow.

    Attributes:
        step_id: Unique step identifier
        agent_id: Executing agent ID
        input_mapping: How to map context to input
        output_mapping: How to map output to context
        condition: Optional execution condition
        timeout: Step timeout in seconds
    """

    step_id: str
    agent_id: str
    input_mapping: dict[str, str] = field(default_factory=dict)
    output_mapping: dict[str, str] = field(default_factory=dict)
    condition: Optional[str] = None
    timeout: float = 300.0


class SequentialExecutor:
    """
    Sequential workflow executor.

    Executes steps in order, passing outputs as inputs
    to subsequent steps with support for conditions and mappings.

    Attributes:
        steps: Ordered list of workflow steps
        agents: Available agents for execution
    """

    def __init__(self) -> None:
        """Initialize sequential executor."""
        self._steps: list[SequentialStep] = []
        self._agents: dict[str, BaseAgent] = {}

    def add_step(
        self,
        step_id: str,
        agent_id: str,
        input_mapping: Optional[dict[str, str]] = None,
        output_mapping: Optional[dict[str, str]] = None,
        condition: Optional[str] = None,
        timeout: float = 300.0,
    ) -> "SequentialExecutor":
        """
        Add step to workflow.

        Args:
            step_id: Step identifier
            agent_id: Agent to execute step
            input_mapping: Context key to input key mapping
            output_mapping: Output key to context key mapping
            condition: Optional condition expression
            timeout: Step timeout

        Returns:
            Self for chaining
        """
        self._steps.append(
            SequentialStep(
                step_id=step_id,
                agent_id=agent_id,
                input_mapping=input_mapping or {},
                output_mapping=output_mapping or {},
                condition=condition,
                timeout=timeout,
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
        initial_context: dict[str, Any],
        correlation_context: Optional[CorrelationContext] = None,
    ) -> dict[str, Any]:
        """
        Execute sequential workflow.

        Args:
            initial_context: Initial workflow context
            correlation_context: Correlation tracking context

        Returns:
            Final context with all outputs

        Raises:
            RuntimeError: If required agent not found
            asyncio.TimeoutError: If step times out
        """
        context = dict(initial_context)
        results = {}

        for step in self._steps:
            if step.agent_id not in self._agents:
                raise RuntimeError(f"Agent '{step.agent_id}' not registered")

            if step.condition and not self._evaluate_condition(step.condition, context):
                continue

            step_input = self._build_step_input(step.input_mapping, context)

            agent = self._agents[step.agent_id]

            async with asyncio.timeout(step.timeout):
                output = await agent.execute(
                    input_data=step_input,
                    context=context,
                    correlation_context=correlation_context,
                )

            results[step.step_id] = {
                "success": True,
                "output": output,
                "agent_id": step.agent_id,
            }

            context = self._apply_output_mapping(step.output_mapping, output, context)
            context["last_step"] = step.step_id
            context["last_output"] = output

        context["sequential_results"] = results
        return context

    def _build_step_input(
        self,
        mapping: dict[str, str],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build step input from context using mapping.

        Args:
            mapping: Input mapping configuration
            context: Current context

        Returns:
            Step input dictionary
        """
        if not mapping:
            return context

        step_input = {}

        for input_key, context_key in mapping.items():
            value = self._get_nested_value(context, context_key)
            if value is not None:
                step_input[input_key] = value

        return step_input

    def _apply_output_mapping(
        self,
        mapping: dict[str, str],
        output: Any,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Apply output mapping to update context.

        Args:
            mapping: Output mapping configuration
            output: Step output
            context: Current context

        Returns:
            Updated context
        """
        if not mapping:
            if isinstance(output, dict):
                context.update(output)
            return context

        new_context = dict(context)

        for output_key, context_key in mapping.items():
            if isinstance(output, dict) and output_key in output:
                self._set_nested_value(new_context, context_key, output[output_key])

        return new_context

    def _evaluate_condition(self, condition: str, context: dict[str, Any]) -> bool:
        try:
            safe_context = {k: v for k, v in context.items() if not k.startswith("_")}
            return _safe_eval_condition(condition, safe_context)
        except Exception:
            return True

    def _get_nested_value(self, obj: Any, path: str) -> Any:
        """
        Get nested value using dot notation.

        Args:
            obj: Object to search
            path: Dot-separated path

        Returns:
            Value or None
        """
        parts = path.split(".")
        current = obj

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, (list, tuple)):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None

            if current is None:
                return None

        return current

    def _set_nested_value(self, obj: dict[str, Any], path: str, value: Any) -> None:
        """
        Set nested value using dot notation.

        Args:
            obj: Object to update
            path: Dot-separated path
            value: Value to set
        """
        parts = path.split(".")

        if len(parts) == 1:
            obj[path] = value
            return

        current = obj

        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value

    @property
    def steps(self) -> list[SequentialStep]:
        """Get workflow steps."""
        return self._steps

    @property
    def step_count(self) -> int:
        """Get number of steps."""
        return len(self._steps)
