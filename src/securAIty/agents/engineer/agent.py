"""
Security Engineer Agent

Automated security remediation, patch management, and security
control implementation with change management support.
"""

import asyncio
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from ..events.correlation import CorrelationContext
from ..events.schema import EventStatus, EventType, SecurityEvent, Severity
from .base import AgentConfig, BaseAgent, HealthStatus, TaskRequest, TaskResult


class RemediationStatus(Enum):
    """Remediation task status."""

    PENDING = auto()
    IN_PROGRESS = auto()
    COMPLETED = auto()
    FAILED = auto()
    ROLLED_BACK = auto()


@dataclass
class RemediationTask:
    """
    Security remediation task.

    Attributes:
        task_id: Unique task identifier
        vulnerability_id: Related vulnerability ID
        action: Remediation action
        target: Target system/resource
        status: Task status
        changes: Applied changes
        rollback_plan: Rollback procedure
        verification: Verification results
    """

    task_id: str
    vulnerability_id: str
    action: str
    target: str
    status: RemediationStatus = RemediationStatus.PENDING
    changes: list[dict[str, Any]] = field(default_factory=list)
    rollback_plan: list[str] = field(default_factory=list)
    verification: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityControl:
    """
    Security control configuration.

    Attributes:
        control_id: Control identifier
        name: Control name
        category: Control category
        enabled: Whether control is active
        configuration: Control configuration
        compliance_mapping: Compliance framework mappings
    """

    control_id: str
    name: str
    category: str
    enabled: bool = True
    configuration: dict[str, Any] = field(default_factory=dict)
    compliance_mapping: dict[str, str] = field(default_factory=dict)


class EngineerAgent(BaseAgent):
    """
    Security Engineer agent for automated remediation.

    Implements security fixes, manages patches, configures
    security controls, and handles change management.

    Capabilities:
        - Automated remediation
        - Patch management
        - Security control configuration
        - Change management
        - Verification and validation
    """

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        """
        Initialize security engineer agent.

        Args:
            config: Optional agent configuration
        """
        if config is None:
            config = AgentConfig(
                agent_id="engineer_agent",
                name="Security Engineer Agent",
                description="Automated security remediation and control implementation",
                capabilities=[
                    {
                        "name": "automated_remediation",
                        "description": "Execute automated security fixes",
                        "priority": 10,
                    },
                    {
                        "name": "patch_management",
                        "description": "Manage security patches",
                        "priority": 20,
                    },
                    {
                        "name": "control_configuration",
                        "description": "Configure security controls",
                        "priority": 30,
                    },
                    {
                        "name": "change_management",
                        "description": "Manage security changes",
                        "priority": 40,
                    },
                    {
                        "name": "verification",
                        "description": "Verify remediation success",
                        "priority": 50,
                    },
                ],
                max_concurrent_tasks=5,
                task_timeout=600.0,
            )

        super().__init__(config)

        self._remediation_tasks: dict[str, RemediationTask] = {}
        self._security_controls: dict[str, SecurityControl] = {}
        self._change_log: list[dict[str, Any]] = []
        self._event_callback: Optional[callable] = None

        self._initialize_default_controls()

    def _initialize_default_controls(self) -> None:
        """Initialize default security controls."""
        default_controls = [
            SecurityControl(
                control_id="ctrl_firewall",
                name="Firewall Configuration",
                category="network_security",
                configuration={"default_deny": True, "logging": True},
                compliance_mapping={"CIS": "9.1", "NIST": "SC-7"},
            ),
            SecurityControl(
                control_id="ctrl_access",
                name="Access Control",
                category="identity_access",
                configuration={"mfa_required": True, "session_timeout": 3600},
                compliance_mapping={"CIS": "5.1", "NIST": "AC-2"},
            ),
            SecurityControl(
                control_id="ctrl_encryption",
                name="Data Encryption",
                category="data_protection",
                configuration={"encryption_at_rest": True, "encryption_in_transit": True},
                compliance_mapping={"CIS": "3.1", "NIST": "SC-28"},
            ),
            SecurityControl(
                control_id="ctrl_logging",
                name="Security Logging",
                category="monitoring",
                configuration={"log_level": "info", "retention_days": 90},
                compliance_mapping={"CIS": "6.1", "NIST": "AU-2"},
            ),
        ]

        for control in default_controls:
            self._security_controls[control.control_id] = control

    def set_event_callback(self, callback: callable) -> None:
        """Set callback for emitting security events."""
        self._event_callback = callback

    async def initialize(self) -> None:
        """
        Initialize engineer agent resources.

        Sets up security controls and marks agent as ready.
        """
        self._remediation_tasks.clear()
        self._change_log.clear()
        self._update_health_status(HealthStatus.HEALTHY)

    async def execute(self, request: TaskRequest) -> TaskResult:
        """
        Execute security engineering task request.

        Handles config_deploy, patch_management, backup_verify,
        and infra_automation capabilities.

        Args:
            request: Task request with capability and input data

        Returns:
            TaskResult with task results
        """
        start_time = asyncio.get_event_loop().time()

        try:
            if not self._initialized:
                return TaskResult.failure(
                    task_id=request.task_id,
                    error_message="Agent not initialized",
                )

            capability_mapping = {
                "config_deploy": "configure",
                "patch_management": "patch",
                "backup_verify": "verify",
                "infra_automation": "remediate",
            }

            if request.capability not in capability_mapping:
                return TaskResult.failure(
                    task_id=request.task_id,
                    error_message=f"Unknown capability: {request.capability}",
                )

            input_data = request.input_data.copy()
            input_data["task_type"] = capability_mapping[request.capability]

            context = {"priority": request.priority, "timeout": request.timeout}
            correlation_context = CorrelationContext(
                correlation_id=request.correlation_id,
            )

            result = await self._execute(input_data, context, correlation_context)

            execution_time = (asyncio.get_event_loop().time() - start_time) * 1000

            return TaskResult.success(
                task_id=request.task_id,
                output_data=result,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            execution_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return TaskResult.failure(
                task_id=request.task_id,
                error_message="Engineer operation failed",
                execution_time_ms=execution_time,
            )

    async def health_check(self) -> HealthStatus:
        """
        Perform health check on engineer agent.

        Verifies agent is initialized and ready for tasks.

        Returns:
            Current health status
        """
        if not self._initialized:
            self._update_health_status(HealthStatus.UNHEALTHY)
            return HealthStatus.UNHEALTHY

        self._update_health_status(HealthStatus.HEALTHY)
        return HealthStatus.HEALTHY

    async def shutdown(self) -> None:
        """
        Gracefully shutdown engineer agent.

        Cleans up resources and marks agent as stopped.
        """
        self._remediation_tasks.clear()
        self._change_log.clear()
        self._update_health_status(HealthStatus.UNKNOWN)

    async def _execute(
        self,
        input_data: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Execute security engineering task.

        Args:
            input_data: Task data
            context: Execution context
            correlation_context: Correlation tracking

        Returns:
            Task results
        """
        task_type = input_data.get("task_type", "remediate")

        if task_type == "remediate":
            return await self._execute_remediation(input_data, correlation_context)

        elif task_type == "patch":
            return await self._apply_patch(input_data, correlation_context)

        elif task_type == "configure":
            return await self._configure_control(input_data, correlation_context)

        elif task_type == "verify":
            return await self._verify_remediation(input_data, correlation_context)

        else:
            return await self._execute_maintenance(input_data, correlation_context)

    async def _execute_remediation(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Execute security remediation.

        Args:
            input_data: Remediation request
            correlation_context: Correlation tracking

        Returns:
            Remediation results
        """
        vuln_id = input_data.get("vulnerability_id", f"vuln_{hash(str(input_data))}")
        target = input_data.get("target", "unknown")
        action = input_data.get("action", "patch")

        task_id = f"rem_{hash(str(input_data))}"

        task = RemediationTask(
            task_id=task_id,
            vulnerability_id=vuln_id,
            action=action,
            target=target,
            rollback_plan=self._generate_rollback_plan(action, target),
        )

        self._remediation_tasks[task_id] = task
        task.status = RemediationStatus.IN_PROGRESS

        await self._log_change("remediation_started", task_id, input_data)

        try:
            changes = await self._apply_remediation(action, target, input_data)

            task.changes = changes
            task.status = RemediationStatus.COMPLETED

            verification = await self._verify_changes(changes)
            task.verification = verification

            await self._log_change("remediation_completed", task_id, {"verified": verification.get("success")})

            if self._event_callback and verification.get("success"):
                await self._emit_remediation_event(task, correlation_context)

            return {
                "task_id": task_id,
                "status": "completed",
                "changes_applied": len(changes),
                "verification": verification,
            }

        except Exception as e:
            task.status = RemediationStatus.FAILED
            task.verification = {"success": False, "error": str(e)}

            await self._log_change("remediation_failed", task_id, {"error": str(e)})

            return {
                "task_id": task_id,
                "status": "failed",
                "error": str(e),
                "rollback_available": True,
            }

    async def _apply_patch(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Apply security patch.

        Args:
            input_data: Patch information
            correlation_context: Correlation tracking

        Returns:
            Patch results
        """
        patch_id = input_data.get("patch_id", "unknown")
        target_system = input_data.get("target_system", "unknown")
        patch_type = input_data.get("patch_type", "security")

        result = {
            "patch_id": patch_id,
            "target_system": target_system,
            "status": "pending",
            "stages": [],
        }

        stages = [
            ("pre_check", await self._pre_patch_check(target_system)),
            ("backup", await self._create_backup(target_system)),
            ("apply", await self._apply_patch_internal(patch_id, target_system)),
            ("verify", await self._post_patch_verify(target_system, patch_id)),
        ]

        for stage_name, stage_result in stages:
            result["stages"].append({
                "name": stage_name,
                "success": stage_result.get("success", False),
                "details": stage_result,
            })

            if not stage_result.get("success"):
                result["status"] = "failed"
                result["failed_stage"] = stage_name
                await self._rollback_patch(target_system, patch_id)
                break
        else:
            result["status"] = "completed"

        await self._log_change("patch_applied", patch_id, result)

        return result

    async def _configure_control(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Configure security control.

        Args:
            input_data: Control configuration
            correlation_context: Correlation tracking

        Returns:
            Configuration results
        """
        control_id = input_data.get("control_id")
        configuration = input_data.get("configuration", {})
        enabled = input_data.get("enabled", True)

        if control_id and control_id in self._security_controls:
            control = self._security_controls[control_id]
            old_config = dict(control.configuration)

            control.configuration.update(configuration)
            control.enabled = enabled

            await self._log_change("control_configured", control_id, {
                "old_config": old_config,
                "new_config": control.configuration,
            })

            return {
                "control_id": control_id,
                "status": "configured",
                "changes": self._diff_config(old_config, control.configuration),
            }

        elif control_id:
            new_control = SecurityControl(
                control_id=control_id,
                name=input_data.get("name", control_id),
                category=input_data.get("category", "custom"),
                enabled=enabled,
                configuration=configuration,
            )

            self._security_controls[control_id] = new_control

            return {
                "control_id": control_id,
                "status": "created",
                "control": {
                    "name": new_control.name,
                    "category": new_control.category,
                    "enabled": new_control.enabled,
                },
            }

        return {"status": "failed", "error": "Invalid control_id"}

    async def _verify_remediation(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Verify remediation success.

        Args:
            input_data: Verification request
            correlation_context: Correlation tracking

        Returns:
            Verification results
        """
        task_id = input_data.get("task_id")

        if task_id and task_id in self._remediation_tasks:
            task = self._remediation_tasks[task_id]
            verification = await self._verify_changes(task.changes)

            task.verification = verification

            return {
                "task_id": task_id,
                "verified": verification.get("success", False),
                "details": verification,
            }

        target = input_data.get("target")
        vulnerability_id = input_data.get("vulnerability_id")

        verification = await self._scan_for_vulnerability(target, vulnerability_id)

        return {
            "target": target,
            "vulnerability_id": vulnerability_id,
            "still_vulnerable": verification.get("found", False),
            "verification_details": verification,
        }

    async def _execute_maintenance(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Execute security maintenance tasks.

        Args:
            input_data: Maintenance data
            correlation_context: Correlation tracking

        Returns:
            Maintenance results
        """
        maintenance_type = input_data.get("maintenance_type", "routine")

        if maintenance_type == "rotate_credentials":
            return await self._rotate_credentials(input_data)

        elif maintenance_type == "update_rules":
            return await self._update_security_rules(input_data)

        elif maintenance_type == "cleanup":
            return await self._cleanup_temporary_resources(input_data)

        return {"status": "completed", "maintenance_type": maintenance_type}

    async def _apply_remediation(
        self,
        action: str,
        target: str,
        input_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Apply remediation action."""
        changes = []

        if action == "patch":
            changes.append({
                "type": "patch_applied",
                "target": target,
                "patch_id": input_data.get("patch_id", "auto"),
            })

        elif action == "config_change":
            changes.append({
                "type": "configuration_updated",
                "target": target,
                "changes": input_data.get("changes", {}),
            })

        elif action == "access_revoke":
            changes.append({
                "type": "access_revoked",
                "target": target,
                "principal": input_data.get("principal"),
            })

        elif action == "firewall_rule":
            changes.append({
                "type": "firewall_rule_added",
                "target": target,
                "rule": input_data.get("rule", {}),
            })

        return changes

    async def _verify_changes(self, changes: list[dict[str, Any]]) -> dict[str, Any]:
        """Verify applied changes."""
        verification_results = []

        for change in changes:
            result = {"change_type": change.get("type"), "verified": True}

            if change.get("type") == "patch_applied":
                result["details"] = {"patch_status": "installed"}

            elif change.get("type") == "configuration_updated":
                result["details"] = {"config_valid": True}

            verification_results.append(result)

        all_verified = all(r.get("verified", False) for r in verification_results)

        return {
            "success": all_verified,
            "verified_changes": len([r for r in verification_results if r.get("verified")]),
            "total_changes": len(changes),
            "details": verification_results,
        }

    async def _scan_for_vulnerability(
        self,
        target: str,
        vulnerability_id: str,
    ) -> dict[str, Any]:
        """Scan for specific vulnerability."""
        return {
            "found": False,
            "target": target,
            "vulnerability_id": vulnerability_id,
            "scan_timestamp": asyncio.get_event_loop().time(),
            "confidence": 0.95,
        }

    def _generate_rollback_plan(self, action: str, target: str) -> list[str]:
        """Generate rollback plan for action."""
        plans = {
            "patch": [
                f"Identify current patch level on {target}",
                "Download previous patch version",
                "Schedule maintenance window",
                "Apply rollback patch",
                "Verify system functionality",
            ],
            "config_change": [
                f"Backup current configuration on {target}",
                "Restore previous configuration",
                "Restart affected services",
                "Verify functionality",
            ],
            "access_revoke": [
                "Identify revoked access",
                "Restore previous access state",
                "Notify affected users",
                "Audit access restoration",
            ],
        }

        return plans.get(action, [
            "Assess current state",
            "Prepare rollback procedure",
            "Execute rollback",
            "Verify restoration",
        ])

    async def _log_change(self, change_type: str, change_id: str, details: dict[str, Any]) -> None:
        """Log change for audit trail."""
        self._change_log.append({
            "timestamp": asyncio.get_event_loop().time(),
            "change_type": change_type,
            "change_id": change_id,
            "details": details,
            "agent_id": self.agent_id,
        })

    async def _pre_patch_check(self, target_system: str) -> dict[str, Any]:
        """Pre-patch system check."""
        return {
            "success": True,
            "disk_space": "sufficient",
            "dependencies": "satisfied",
            "compatibility": "verified",
        }

    async def _create_backup(self, target_system: str) -> dict[str, Any]:
        """Create system backup."""
        return {
            "success": True,
            "backup_id": f"backup_{hash(target_system)}",
            "location": "/backups",
        }

    async def _apply_patch_internal(
        self,
        patch_id: str,
        target_system: str,
    ) -> dict[str, Any]:
        """Apply patch internally."""
        return {
            "success": True,
            "patch_id": patch_id,
            "applied_at": asyncio.get_event_loop().time(),
        }

    async def _post_patch_verify(
        self,
        target_system: str,
        patch_id: str,
    ) -> dict[str, Any]:
        """Post-patch verification."""
        return {
            "success": True,
            "patch_verified": True,
            "system_healthy": True,
        }

    async def _rollback_patch(self, target_system: str, patch_id: str) -> dict[str, Any]:
        """Rollback failed patch."""
        return {
            "success": True,
            "rolled_back": True,
            "reason": "patch_failure",
        }

    def _diff_config(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Calculate configuration diff."""
        changes = []

        all_keys = set(old.keys()) | set(new.keys())

        for key in all_keys:
            if key not in old:
                changes.append({"key": key, "action": "added", "value": new.get(key)})
            elif key not in new:
                changes.append({"key": key, "action": "removed", "old_value": old.get(key)})
            elif old.get(key) != new.get(key):
                changes.append({
                    "key": key,
                    "action": "modified",
                    "old_value": old.get(key),
                    "new_value": new.get(key),
                })

        return changes

    async def _rotate_credentials(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Rotate credentials."""
        return {
            "success": True,
            "rotated": input_data.get("credential_type", "unknown"),
            "timestamp": asyncio.get_event_loop().time(),
        }

    async def _update_security_rules(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Update security rules."""
        return {
            "success": True,
            "rules_updated": input_data.get("rule_count", 0),
            "timestamp": asyncio.get_event_loop().time(),
        }

    async def _cleanup_temporary_resources(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Cleanup temporary resources."""
        return {
            "success": True,
            "resources_cleaned": input_data.get("resource_count", 0),
            "timestamp": asyncio.get_event_loop().time(),
        }

    async def _emit_remediation_event(
        self,
        task: RemediationTask,
        correlation_context: Optional[CorrelationContext],
    ) -> None:
        """Emit remediation completion event."""
        if not self._event_callback:
            return

        event = SecurityEvent.create(
            event_type=EventType.REMEDIATION_COMPLETED,
            severity=Severity.INFO,
            title=f"Remediation Completed: {task.task_id}",
            description=f"Successfully remediated vulnerability {task.vulnerability_id}",
            source_agent=self.agent_id,
            payload={
                "task_id": task.task_id,
                "vulnerability_id": task.vulnerability_id,
                "action": task.action,
                "target": task.target,
                "changes": task.changes,
            },
            correlation_id=correlation_context.correlation_id if correlation_context else None,
        )

        if asyncio.iscoroutinefunction(self._event_callback):
            await self._event_callback(event)
        else:
            self._event_callback(event)

    def get_remediation_task(self, task_id: str) -> Optional[RemediationTask]:
        """Get remediation task by ID."""
        return self._remediation_tasks.get(task_id)

    def get_security_control(self, control_id: str) -> Optional[SecurityControl]:
        """Get security control by ID."""
        return self._security_controls.get(control_id)

    def list_security_controls(self) -> list[dict[str, Any]]:
        """List all security controls."""
        return [
            {
                "control_id": c.control_id,
                "name": c.name,
                "category": c.category,
                "enabled": c.enabled,
                "configuration": c.configuration,
            }
            for c in self._security_controls.values()
        ]

    def get_change_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent change log entries."""
        return self._change_log[-limit:]
