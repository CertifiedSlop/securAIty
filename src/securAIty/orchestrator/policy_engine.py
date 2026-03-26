"""
Policy Engine

Security policy evaluation and enforcement for agent tasks
with support for complex conditions and rule-based decisions.
"""

import asyncio
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional, Union


class PolicyEffect(Enum):
    """Policy decision effect."""

    ALLOW = auto()
    DENY = auto()
    CONDITIONAL = auto()


class ConditionOperator(Enum):
    """Condition evaluation operators."""

    EQUALS = "eq"
    NOT_EQUALS = "neq"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    GREATER_EQUALS = "gte"
    LESS_EQUALS = "lte"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


@dataclass
class PolicyCondition:
    """
    Single condition for policy evaluation.

    Attributes:
        field: Field path to evaluate (dot notation for nested)
        operator: Comparison operator
        value: Value to compare against
        description: Human-readable condition description
    """

    field: str
    operator: ConditionOperator
    value: Any
    description: str = ""

    def evaluate(self, context: dict[str, Any]) -> bool:
        """
        Evaluate condition against context.

        Args:
            context: Evaluation context

        Returns:
            True if condition passes
        """
        actual_value = self._get_field_value(context, self.field)

        if self.operator == ConditionOperator.EXISTS:
            return actual_value is not None

        if self.operator == ConditionOperator.NOT_EXISTS:
            return actual_value is None

        if actual_value is None:
            return False

        return self._compare(actual_value, self.value, self.operator)

    def _get_field_value(self, context: dict[str, Any], field_path: str) -> Any:
        """
        Get nested field value using dot notation.

        Args:
            context: Context dictionary
            field_path: Dot-separated field path

        Returns:
            Field value or None
        """
        parts = field_path.split(".")
        current = context

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, (list, tuple)):
                try:
                    index = int(part)
                    current = current[index] if 0 <= index < len(current) else None
                except (ValueError, IndexError):
                    return None
            else:
                return None

            if current is None:
                return None

        return current

    def _compare(
        self,
        actual: Any,
        expected: Any,
        operator: ConditionOperator,
    ) -> bool:
        """
        Compare values using operator.

        Args:
            actual: Actual value
            expected: Expected value
            operator: Comparison operator

        Returns:
            Comparison result
        """
        try:
            if operator == ConditionOperator.EQUALS:
                return actual == expected

            elif operator == ConditionOperator.NOT_EQUALS:
                return actual != expected

            elif operator == ConditionOperator.GREATER_THAN:
                return actual > expected

            elif operator == ConditionOperator.LESS_THAN:
                return actual < expected

            elif operator == ConditionOperator.GREATER_EQUALS:
                return actual >= expected

            elif operator == ConditionOperator.LESS_EQUALS:
                return actual <= expected

            elif operator == ConditionOperator.IN:
                return actual in expected

            elif operator == ConditionOperator.NOT_IN:
                return actual not in expected

            elif operator == ConditionOperator.CONTAINS:
                return expected in actual

            elif operator == ConditionOperator.STARTS_WITH:
                return str(actual).startswith(str(expected))

            elif operator == ConditionOperator.ENDS_WITH:
                return str(actual).endswith(str(expected))

            elif operator == ConditionOperator.REGEX:
                import re

                return bool(re.search(expected, str(actual)))

        except (TypeError, ValueError):
            return False

        return False


@dataclass
class PolicyRule:
    """
    Policy rule with conditions and effect.

    Attributes:
        rule_id: Unique rule identifier
        name: Human-readable name
        conditions: List of conditions (AND logic)
        effect: Policy effect if conditions match
        priority: Rule priority (lower = higher priority)
        description: Rule description
        enabled: Whether rule is active
    """

    rule_id: str
    name: str
    conditions: list[PolicyCondition]
    effect: PolicyEffect
    priority: int = 100
    description: str = ""
    enabled: bool = True

    def evaluate(self, context: dict[str, Any]) -> Optional[PolicyEffect]:
        """
        Evaluate rule against context.

        Args:
            context: Evaluation context

        Returns:
            Policy effect if matched, None otherwise
        """
        if not self.enabled:
            return None

        if not self.conditions:
            return self.effect

        all_match = all(condition.evaluate(context) for condition in self.conditions)

        return self.effect if all_match else None


@dataclass
class PolicyResult:
    """
    Result of policy evaluation.

    Attributes:
        allowed: Whether action is allowed
        effect: Policy effect
        reason: Human-readable reason
        matched_rules: List of matched rule IDs
        denied_by: Rule ID that denied (if applicable)
        conditions: Any conditions for conditional allow
        metadata: Additional evaluation metadata
    """

    allowed: bool
    effect: PolicyEffect = PolicyEffect.ALLOW
    reason: str = ""
    matched_rules: list[str] = field(default_factory=list)
    denied_by: Optional[str] = None
    conditions: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allow(
        cls,
        matched_rules: Optional[list[str]] = None,
        reason: str = "",
        conditions: Optional[dict[str, Any]] = None,
    ) -> "PolicyResult":
        """
        Create allow result.

        Args:
            matched_rules: Matched rule IDs
            reason: Allow reason
            conditions: Conditional requirements

        Returns:
            Allow result
        """
        return cls(
            allowed=True,
            effect=PolicyEffect.ALLOW,
            reason=reason or "Policy allows action",
            matched_rules=matched_rules or [],
            conditions=conditions or {},
        )

    @classmethod
    def deny(
        cls,
        denied_by: str,
        reason: str = "",
        matched_rules: Optional[list[str]] = None,
    ) -> "PolicyResult":
        """
        Create deny result.

        Args:
            denied_by: Denying rule ID
            reason: Denial reason
            matched_rules: Matched rule IDs

        Returns:
            Deny result
        """
        return cls(
            allowed=False,
            effect=PolicyEffect.DENY,
            reason=reason or "Policy denies action",
            denied_by=denied_by,
            matched_rules=matched_rules or [],
        )

    @classmethod
    def conditional(
        cls,
        matched_rules: list[str],
        conditions: dict[str, Any],
        reason: str = "",
    ) -> "PolicyResult":
        """
        Create conditional allow result.

        Args:
            matched_rules: Matched rule IDs
            conditions: Required conditions
            reason: Reason for conditional

        Returns:
            Conditional result
        """
        return cls(
            allowed=True,
            effect=PolicyEffect.CONDITIONAL,
            reason=reason or "Action allowed with conditions",
            matched_rules=matched_rules,
            conditions=conditions,
        )


@dataclass
class Policy:
    """
    Security policy with rules and metadata.

    Attributes:
        policy_id: Unique policy identifier
        name: Human-readable name
        description: Policy description
        rules: Policy rules
        enabled: Whether policy is active
        version: Policy version
        tags: Categorization tags
    """

    policy_id: str
    name: str
    description: str = ""
    rules: list[PolicyRule] = field(default_factory=list)
    enabled: bool = True
    version: str = "1.0.0"
    tags: list[str] = field(default_factory=list)

    def add_rule(self, rule: PolicyRule) -> "Policy":
        """
        Add rule to policy.

        Args:
            rule: Rule to add

        Returns:
            Self for chaining
        """
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
        return self

    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove rule from policy.

        Args:
            rule_id: Rule ID to remove

        Returns:
            True if removed
        """
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        return len(self.rules) < initial_len


class PolicyEngine:
    """
    Security policy evaluation engine.

    Evaluates tasks and actions against registered policies,
    enforcing allow/deny decisions with detailed audit trails.

    Attributes:
        _policies: Registered policies by ID
        _default_effect: Default effect when no rules match
        _evaluation_timeout: Rule evaluation timeout
    """

    def __init__(
        self,
        default_effect: PolicyEffect = PolicyEffect.ALLOW,
        evaluation_timeout: float = 5.0,
    ) -> None:
        """
        Initialize policy engine.

        Args:
            default_effect: Default effect when no rules match
            evaluation_timeout: Evaluation timeout in seconds
        """
        self._policies: dict[str, Policy] = {}
        self._default_effect = default_effect
        self._evaluation_timeout = evaluation_timeout
        self._custom_evaluators: dict[str, Callable] = {}

    def register_policy(self, policy: Policy) -> str:
        """
        Register a policy.

        Args:
            policy: Policy to register

        Returns:
            Policy ID
        """
        self._policies[policy.policy_id] = policy
        return policy.policy_id

    def unregister_policy(self, policy_id: str) -> bool:
        """
        Remove policy.

        Args:
            policy_id: Policy ID to remove

        Returns:
            True if removed
        """
        if policy_id in self._policies:
            del self._policies[policy_id]
            return True
        return False

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """
        Get policy by ID.

        Args:
            policy_id: Policy identifier

        Returns:
            Policy or None
        """
        return self._policies.get(policy_id)

    def list_policies(self) -> list[Policy]:
        """
        Get all registered policies.

        Returns:
            List of policies
        """
        return list(self._policies.values())

    def enable_policy(self, policy_id: str) -> bool:
        """
        Enable a policy.

        Args:
            policy_id: Policy ID

        Returns:
            True if enabled
        """
        if policy_id in self._policies:
            self._policies[policy_id].enabled = True
            return True
        return False

    def disable_policy(self, policy_id: str) -> bool:
        """
        Disable a policy.

        Args:
            policy_id: Policy ID

        Returns:
            True if disabled
        """
        if policy_id in self._policies:
            self._policies[policy_id].enabled = False
            return True
        return False

    def register_evaluator(
        self,
        name: str,
        evaluator: Callable[[dict[str, Any]], PolicyResult],
    ) -> None:
        """
        Register custom evaluator function.

        Args:
            name: Evaluator name
            evaluator: Evaluation function
        """
        self._custom_evaluators[name] = evaluator

    async def evaluate_task(
        self,
        task: dict[str, Any],
        context: dict[str, Any],
    ) -> PolicyResult:
        """
        Evaluate task against all policies.

        Args:
            task: Task definition
            context: Evaluation context

        Returns:
            Policy evaluation result
        """
        evaluation_context = {
            "task": task,
            "context": context,
            "timestamp": asyncio.get_event_loop().time(),
        }

        return await self._evaluate(evaluation_context)

    async def evaluate_action(
        self,
        action: str,
        resource: str,
        subject: str,
        context: Optional[dict[str, Any]] = None,
    ) -> PolicyResult:
        """
        Evaluate action against policies.

        Args:
            action: Action being performed
            resource: Target resource
            subject: Acting subject
            context: Additional context

        Returns:
            Policy evaluation result
        """
        evaluation_context = {
            "action": action,
            "resource": resource,
            "subject": subject,
            "context": context or {},
            "timestamp": asyncio.get_event_loop().time(),
        }

        return await self._evaluate(evaluation_context)

    async def _evaluate(self, context: dict[str, Any]) -> PolicyResult:
        """
        Internal evaluation logic.

        Args:
            context: Evaluation context

        Returns:
            Policy result
        """
        matched_rules: list[str] = []
        deny_rules: list[PolicyRule] = []
        allow_rules: list[PolicyRule] = []
        conditional_rules: list[PolicyRule] = []
        conditions: dict[str, Any] = {}

        try:
            async with asyncio.timeout(self._evaluation_timeout):
                for policy in self._policies.values():
                    if not policy.enabled:
                        continue

                    for rule in policy.rules:
                        if not rule.enabled:
                            continue

                        try:
                            effect = await self._evaluate_rule(rule, context)

                            if effect:
                                matched_rules.append(rule.rule_id)

                                if effect == PolicyEffect.DENY:
                                    deny_rules.append(rule)
                                elif effect == PolicyEffect.ALLOW:
                                    allow_rules.append(rule)
                                elif effect == PolicyEffect.CONDITIONAL:
                                    conditional_rules.append(rule)

                        except asyncio.TimeoutError:
                            continue
                        except Exception:
                            continue

        except asyncio.TimeoutError:
            return PolicyResult.deny(
                denied_by="timeout",
                reason="Policy evaluation timeout",
            )

        if deny_rules:
            deny_rules.sort(key=lambda r: r.priority)
            return PolicyResult.deny(
                denied_by=deny_rules[0].rule_id,
                reason=f"Denied by rule: {deny_rules[0].name}",
                matched_rules=matched_rules,
            )

        if conditional_rules:
            for rule in conditional_rules:
                rule_conditions = self._extract_conditions(rule, context)
                conditions.update(rule_conditions)

            return PolicyResult.conditional(
                matched_rules=matched_rules,
                conditions=conditions,
                reason="Allowed with conditions",
            )

        if allow_rules:
            return PolicyResult.allow(
                matched_rules=matched_rules,
                reason=f"Allowed by {len(allow_rules)} rule(s)",
            )

        if self._default_effect == PolicyEffect.ALLOW:
            return PolicyResult.allow(
                matched_rules=matched_rules,
                reason="Default allow - no matching rules",
            )

        return PolicyResult.deny(
            denied_by="default",
            reason="Default deny - no matching rules",
            matched_rules=matched_rules,
        )

    async def _evaluate_rule(
        self,
        rule: PolicyRule,
        context: dict[str, Any],
    ) -> Optional[PolicyEffect]:
        """
        Evaluate single rule.

        Args:
            rule: Rule to evaluate
            context: Evaluation context

        Returns:
            Policy effect if matched
        """
        return rule.evaluate(context)

    def _extract_conditions(
        self,
        rule: PolicyRule,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Extract conditions from rule for conditional allow.

        Args:
            rule: Policy rule
            context: Evaluation context

        Returns:
            Extracted conditions
        """
        conditions = {}

        for condition in rule.conditions:
            key = f"{condition.field}_{condition.operator.value}"
            conditions[key] = {
                "field": condition.field,
                "operator": condition.operator.value,
                "expected": condition.value,
            }

        return conditions

    def create_policy_builder(self, policy_id: str, name: str) -> "PolicyBuilder":
        """
        Create policy builder for fluent construction.

        Args:
            policy_id: Policy ID
            name: Policy name

        Returns:
            Policy builder instance
        """
        return PolicyBuilder(policy_id, name, self)


class PolicyBuilder:
    """
    Fluent builder for policy construction.

    Enables programmatic policy creation with method chaining.
    """

    def __init__(
        self,
        policy_id: str,
        name: str,
        engine: PolicyEngine,
    ) -> None:
        """
        Initialize policy builder.

        Args:
            policy_id: Policy ID
            name: Policy name
            engine: Parent policy engine
        """
        self._policy = Policy(policy_id=policy_id, name=name)
        self._engine = engine

    def with_description(self, description: str) -> "PolicyBuilder":
        """
        Set policy description.

        Args:
            description: Policy description

        Returns:
            Self for chaining
        """
        self._policy.description = description
        return self

    def with_version(self, version: str) -> "PolicyBuilder":
        """
        Set policy version.

        Args:
            version: Version string

        Returns:
            Self for chaining
        """
        self._policy.version = version
        return self

    def with_tags(self, tags: list[str]) -> "PolicyBuilder":
        """
        Set policy tags.

        Args:
            tags: Tag list

        Returns:
            Self for chaining
        """
        self._policy.tags = tags
        return self

    def add_rule(
        self,
        rule_id: str,
        name: str,
        effect: PolicyEffect,
        priority: int = 100,
    ) -> "PolicyRuleBuilder":
        """
        Start adding a rule.

        Args:
            rule_id: Rule ID
            name: Rule name
            effect: Rule effect
            priority: Rule priority

        Returns:
            Rule builder for conditions
        """
        return PolicyRuleBuilder(self, rule_id, name, effect, priority)

    def build(self) -> Policy:
        """
        Build and register policy.

        Returns:
            Built policy
        """
        self._policy.rules.sort(key=lambda r: r.priority)
        self._engine.register_policy(self._policy)
        return self._policy


class PolicyRuleBuilder:
    """
    Fluent builder for policy rule construction.
    """

    def __init__(
        self,
        policy_builder: PolicyBuilder,
        rule_id: str,
        name: str,
        effect: PolicyEffect,
        priority: int = 100,
    ) -> None:
        """
        Initialize rule builder.

        Args:
            policy_builder: Parent policy builder
            rule_id: Rule ID
            name: Rule name
            effect: Rule effect
            priority: Rule priority
        """
        self._policy_builder = policy_builder
        self._rule = PolicyRule(
            rule_id=rule_id,
            name=name,
            conditions=[],
            effect=effect,
            priority=priority,
        )

    def when(
        self,
        field: str,
        operator: Union[ConditionOperator, str],
        value: Any,
        description: str = "",
    ) -> "PolicyRuleBuilder":
        """
        Add condition to rule.

        Args:
            field: Field path
            operator: Comparison operator
            value: Comparison value
            description: Condition description

        Returns:
            Self for chaining
        """
        if isinstance(operator, str):
            operator = ConditionOperator(operator)

        self._rule.conditions.append(
            PolicyCondition(
                field=field,
                operator=operator,
                value=value,
                description=description,
            )
        )
        return self

    def finish(self) -> PolicyBuilder:
        """
        Finish rule and return to policy builder.

        Returns:
            Parent policy builder
        """
        self._policy_builder._policy.add_rule(self._rule)
        return self._policy_builder
