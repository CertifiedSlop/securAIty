"""
State Manager

State checkpoint and recovery for orchestrator workflows
with persistence support and crash recovery capabilities.
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional


class RecoveryStrategy(Enum):
    """State recovery strategies."""

    RESTART_FROM_CHECKPOINT = auto()
    RESTART_FROM_BEGINNING = auto()
    SKIP_FAILED_TASKS = auto()
    MANUAL_RECOVERY = auto()


@dataclass
class StateCheckpoint:
    """
    Checkpoint of orchestrator state.

    Attributes:
        checkpoint_id: Unique checkpoint identifier
        orchestrator_id: Orchestrator identifier
        orchestrator_status: Orchestrator status at checkpoint
        workflow_states: Workflow states at checkpoint
        timestamp: Checkpoint creation time
        metadata: Additional checkpoint metadata
    """

    checkpoint_id: str
    orchestrator_id: str
    orchestrator_status: str
    workflow_states: dict[str, Any]
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize checkpoint to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "checkpoint_id": self.checkpoint_id,
            "orchestrator_id": self.orchestrator_id,
            "orchestrator_status": self.orchestrator_status,
            "workflow_states": self.workflow_states,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StateCheckpoint":
        """
        Deserialize checkpoint from dictionary.

        Args:
            data: Dictionary data

        Returns:
            Reconstructed checkpoint
        """
        return cls(
            checkpoint_id=data.get("checkpoint_id", ""),
            orchestrator_id=data.get("orchestrator_id", ""),
            orchestrator_status=data.get("orchestrator_status", ""),
            workflow_states=data.get("workflow_states", {}),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).timestamp()),
            metadata=data.get("metadata", {}),
        )

    def to_json(self) -> str:
        """
        Serialize checkpoint to JSON string.

        Returns:
            JSON string
        """
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_json(cls, json_str: str) -> "StateCheckpoint":
        """
        Deserialize checkpoint from JSON string.

        Args:
            json_str: JSON string

        Returns:
            Reconstructed checkpoint
        """
        return cls.from_dict(json.loads(json_str))


@dataclass
class RecoveryPlan:
    """
    Plan for recovering from a checkpoint.

    Attributes:
        checkpoint: Source checkpoint
        strategy: Recovery strategy to use
        workflows_to_resume: Workflow IDs to resume
        workflows_to_skip: Workflow IDs to skip
        tasks_to_retry: Task IDs to retry
        estimated_recovery_time: Estimated recovery duration
    """

    checkpoint: StateCheckpoint
    strategy: RecoveryStrategy
    workflows_to_resume: list[str] = field(default_factory=list)
    workflows_to_skip: list[str] = field(default_factory=list)
    tasks_to_retry: list[str] = field(default_factory=list)
    estimated_recovery_time: float = 0.0

    @classmethod
    def create(
        cls,
        checkpoint: StateCheckpoint,
        strategy: RecoveryStrategy,
    ) -> "RecoveryPlan":
        """
        Create recovery plan from checkpoint.

        Args:
            checkpoint: Source checkpoint
            strategy: Recovery strategy

        Returns:
            New recovery plan
        """
        plan = cls(checkpoint=checkpoint, strategy=strategy)

        if strategy == RecoveryStrategy.RESTART_FROM_CHECKPOINT:
            for workflow_id, workflow_state in checkpoint.workflow_states.items():
                status = workflow_state.get("status", "")
                if status in ("RUNNING", "PAUSED"):
                    plan.workflows_to_resume.append(workflow_id)

        elif strategy == RecoveryStrategy.SKIP_FAILED_TASKS:
            for workflow_id, workflow_state in checkpoint.workflow_states.items():
                results = workflow_state.get("results", {})
                for task_id, result in results.items():
                    if not result.get("success", True):
                        plan.tasks_to_retry.append(task_id)
                    else:
                        plan.workflows_to_resume.append(workflow_id)

        return plan


class StateManager:
    """
    State persistence and recovery manager.

    Manages checkpoint creation, loading, and recovery
    for orchestrator workflows with configurable persistence.

    Attributes:
        orchestrator_id: Owner orchestrator identifier
        checkpoint_interval: Checkpoint creation interval
        storage_path: Path for checkpoint storage
    """

    def __init__(
        self,
        orchestrator_id: str,
        checkpoint_interval: int = 10,
        storage_path: Optional[str] = None,
    ) -> None:
        """
        Initialize state manager.

        Args:
            orchestrator_id: Owner orchestrator ID
            checkpoint_interval: Checkpoint frequency (tasks)
            storage_path: Optional storage directory
        """
        self.orchestrator_id = orchestrator_id
        self.checkpoint_interval = checkpoint_interval
        self.storage_path = Path(storage_path) if storage_path else Path("./checkpoints")

        self._checkpoints: dict[str, StateCheckpoint] = {}
        self._task_count = 0
        self._last_checkpoint_time = datetime.now(timezone.utc).timestamp()
        self._lock = asyncio.Lock()

        self.storage_path.mkdir(parents=True, exist_ok=True)

    async def save_checkpoint(
        self,
        checkpoint: StateCheckpoint,
    ) -> str:
        """
        Save checkpoint to storage.

        Args:
            checkpoint: Checkpoint to save

        Returns:
            Checkpoint ID
        """
        async with self._lock:
            self._checkpoints[checkpoint.checkpoint_id] = checkpoint

            checkpoint_file = self.storage_path / f"{checkpoint.checkpoint_id}.json"

            try:
                async with asyncio.Lock():
                    with open(checkpoint_file, "w") as f:
                        f.write(checkpoint.to_json())

                self._last_checkpoint_time = datetime.now(timezone.utc).timestamp()

            except Exception as e:
                raise RuntimeError(f"Failed to save checkpoint: {e}") from e

            return checkpoint.checkpoint_id

    async def load_checkpoint(
        self,
        checkpoint_id: str,
    ) -> Optional[StateCheckpoint]:
        """
        Load checkpoint from storage.

        Args:
            checkpoint_id: Checkpoint ID to load

        Returns:
            Checkpoint or None if not found
        """
        if checkpoint_id in self._checkpoints:
            return self._checkpoints[checkpoint_id]

        checkpoint_file = self.storage_path / f"{checkpoint_id}.json"

        if not checkpoint_file.exists():
            return None

        try:
            with open(checkpoint_file, "r") as f:
                content = f.read()

            checkpoint = StateCheckpoint.from_json(content)
            self._checkpoints[checkpoint_id] = checkpoint

            return checkpoint

        except Exception:
            return None

    async def get_latest_checkpoint(self) -> Optional[StateCheckpoint]:
        """
        Get most recent checkpoint.

        Returns:
            Latest checkpoint or None
        """
        checkpoint_files = list(self.storage_path.glob("*.json"))

        if not checkpoint_files:
            if self._checkpoints:
                return max(self._checkpoints.values(), key=lambda c: c.timestamp)
            return None

        latest_file = max(checkpoint_files, key=lambda f: f.stat().st_mtime)
        checkpoint_id = latest_file.stem

        return await self.load_checkpoint(checkpoint_id)

    async def list_checkpoints(self) -> list[StateCheckpoint]:
        """
        List all available checkpoints.

        Returns:
            List of checkpoints
        """
        checkpoint_files = list(self.storage_path.glob("*.json"))

        checkpoints = []

        for file in checkpoint_files:
            checkpoint = await self.load_checkpoint(file.stem)
            if checkpoint:
                checkpoints.append(checkpoint)

        checkpoints.extend(
            c for c in self._checkpoints.values()
            if c.checkpoint_id not in [cp.checkpoint_id for cp in checkpoints]
        )

        return sorted(checkpoints, key=lambda c: c.timestamp, reverse=True)

    async def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """
        Delete a checkpoint.

        Args:
            checkpoint_id: Checkpoint ID to delete

        Returns:
            True if deleted
        """
        async with self._lock:
            if checkpoint_id in self._checkpoints:
                del self._checkpoints[checkpoint_id]

            checkpoint_file = self.storage_path / f"{checkpoint_id}.json"

            if checkpoint_file.exists():
                checkpoint_file.unlink()
                return True

            return checkpoint_id not in self._checkpoints

    async def create_recovery_plan(
        self,
        checkpoint_id: str,
        strategy: RecoveryStrategy,
    ) -> Optional[RecoveryPlan]:
        """
        Create recovery plan from checkpoint.

        Args:
            checkpoint_id: Source checkpoint ID
            strategy: Recovery strategy

        Returns:
            Recovery plan or None if checkpoint not found
        """
        checkpoint = await self.load_checkpoint(checkpoint_id)

        if not checkpoint:
            return None

        return RecoveryPlan.create(checkpoint, strategy)

    async def execute_recovery(
        self,
        plan: RecoveryPlan,
    ) -> dict[str, Any]:
        """
        Execute recovery plan.

        Args:
            plan: Recovery plan to execute

        Returns:
            Recovery results
        """
        results = {
            "success": True,
            "recovered_workflows": [],
            "skipped_workflows": [],
            "retried_tasks": [],
            "errors": [],
        }

        if plan.strategy == RecoveryStrategy.RESTART_FROM_BEGINNING:
            return results

        if plan.strategy == RecoveryStrategy.MANUAL_RECOVERY:
            results["success"] = False
            results["message"] = "Manual recovery required"
            return results

        for workflow_id in plan.workflows_to_resume:
            workflow_state = plan.checkpoint.workflow_states.get(workflow_id)
            if workflow_state:
                results["recovered_workflows"].append(workflow_id)

        for workflow_id in plan.workflows_to_skip:
            results["skipped_workflows"].append(workflow_id)

        for task_id in plan.tasks_to_retry:
            results["retried_tasks"].append(task_id)

        return results

    def should_checkpoint(self) -> bool:
        """
        Check if checkpoint should be created.

        Returns:
            True if checkpoint interval reached
        """
        self._task_count += 1
        return self._task_count % self.checkpoint_interval == 0

    def reset_checkpoint_counter(self) -> None:
        """Reset task counter after checkpoint."""
        self._task_count = 0

    async def cleanup_old_checkpoints(
        self,
        max_age_days: int = 7,
        keep_count: int = 10,
    ) -> int:
        """
        Remove old checkpoints.

        Args:
            max_age_days: Maximum checkpoint age in days
            keep_count: Minimum checkpoints to keep

        Returns:
            Number of deleted checkpoints
        """
        checkpoints = await self.list_checkpoints()

        if len(checkpoints) <= keep_count:
            return 0

        now = datetime.now(timezone.utc).timestamp()
        max_age_seconds = max_age_days * 86400

        deleted = 0

        for checkpoint in checkpoints[keep_count:]:
            age = now - checkpoint.timestamp

            if age > max_age_seconds:
                if await self.delete_checkpoint(checkpoint.checkpoint_id):
                    deleted += 1

        return deleted

    async def export_state(self, output_path: str) -> bool:
        """
        Export full state to file.

        Args:
            output_path: Output file path

        Returns:
            True if exported
        """
        try:
            checkpoints = await self.list_checkpoints()

            export_data = {
                "orchestrator_id": self.orchestrator_id,
                "export_timestamp": datetime.now(timezone.utc).isoformat(),
                "checkpoints": [cp.to_dict() for cp in checkpoints],
            }

            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2, default=str)

            return True

        except Exception:
            return False

    async def import_state(self, input_path: str) -> int:
        """
        Import state from file.

        Args:
            input_path: Input file path

        Returns:
            Number of checkpoints imported
        """
        try:
            with open(input_path, "r") as f:
                import_data = json.load(f)

            imported = 0

            for cp_data in import_data.get("checkpoints", []):
                checkpoint = StateCheckpoint.from_dict(cp_data)
                await self.save_checkpoint(checkpoint)
                imported += 1

            return imported

        except Exception:
            return 0
