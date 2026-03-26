"""
Agent Repository

Repository for agent operations with specialized queries.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func, and_, desc, or_
from sqlalchemy.ext.asyncio import AsyncSession

from securAIty.storage.models import Agent, AgentTask, AgentType, AgentStatus
from securAIty.storage.repositories.base import BaseRepository


class AgentRepository(BaseRepository[Agent]):
    """
    Repository for agent operations.

    Provides specialized queries and operations for security agents.
    """

    def __init__(self, session: AsyncSession) -> None:
        """
        Initialize agent repository.

        Args:
            session: Async SQLAlchemy session
        """
        super().__init__(session, Agent)

    async def get_by_type(
        self,
        agent_type: AgentType,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Agent]:
        """
        Get agents by type.

        Args:
            agent_type: Agent type enum
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching agents
        """
        stmt = select(Agent).where(Agent.agent_type == agent_type.value)
        stmt = stmt.order_by(desc(Agent.registered_at))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_status(
        self,
        status: AgentStatus,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Agent]:
        """
        Get agents by status.

        Args:
            status: Agent status enum
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching agents
        """
        stmt = select(Agent).where(Agent.status == status.value)
        stmt = stmt.order_by(desc(Agent.registered_at))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_available_agents(
        self,
        agent_type: Optional[AgentType] = None,
    ) -> List[Agent]:
        """
        Get available agents for task assignment.

        Args:
            agent_type: Optional agent type filter

        Returns:
            List of available agents
        """
        available_statuses = [AgentStatus.IDLE.value, AgentStatus.RUNNING.value]
        stmt = select(Agent).where(Agent.status.in_(available_statuses))
        
        if agent_type:
            stmt = stmt.where(Agent.agent_type == agent_type.value)
        
        stmt = stmt.order_by(desc(Agent.last_heartbeat))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_name(
        self,
        name: str,
    ) -> Optional[Agent]:
        """
        Get agent by name.

        Args:
            name: Agent name

        Returns:
            Agent or None if not found
        """
        return await self.get_first({"name": name})

    async def update_status(
        self,
        agent_id: int,
        status: AgentStatus,
    ) -> Optional[Agent]:
        """
        Update agent status.

        Args:
            agent_id: Agent ID
            status: New status

        Returns:
            Updated agent or None if not found
        """
        return await self.update(agent_id, {"status": status.value})

    async def update_heartbeat(
        self,
        agent_id: int,
    ) -> Optional[Agent]:
        """
        Update agent heartbeat timestamp.

        Args:
            agent_id: Agent ID

        Returns:
            Updated agent or None if not found
        """
        return await self.update(
            agent_id,
            {"last_heartbeat": datetime.now(timezone.utc)},
        )

    async def get_unhealthy_agents(
        self,
        heartbeat_threshold_seconds: int = 60,
    ) -> List[Agent]:
        """
        Get unhealthy agents (missed heartbeats).

        Args:
            heartbeat_threshold_seconds: Heartbeat timeout threshold

        Returns:
            List of unhealthy agents
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=heartbeat_threshold_seconds)
        unhealthy_statuses = [AgentStatus.ERROR.value, AgentStatus.UNREACHABLE.value]
        
        stmt = select(Agent).where(
            or_(
                Agent.status.in_(unhealthy_statuses),
                and_(
                    Agent.last_heartbeat != None,
                    Agent.last_heartbeat < cutoff,
                ),
            )
        )
        stmt = stmt.order_by(desc(Agent.last_heartbeat))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def mark_unreachable(
        self,
        heartbeat_threshold_seconds: int = 60,
    ) -> int:
        """
        Mark agents as unreachable based on heartbeat.

        Args:
            heartbeat_threshold_seconds: Heartbeat timeout threshold

        Returns:
            Number of agents marked unreachable
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=heartbeat_threshold_seconds)
        active_statuses = [AgentStatus.IDLE.value, AgentStatus.RUNNING.value, AgentStatus.BUSY.value]
        
        from sqlalchemy import update
        stmt = update(Agent).where(
            and_(
                Agent.status.in_(active_statuses),
                Agent.last_heartbeat != None,
                Agent.last_heartbeat < cutoff,
            )
        ).values(
            status=AgentStatus.UNREACHABLE.value,
            updated_at=datetime.now(timezone.utc),
        )
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount or 0

    async def get_agents_by_capability(
        self,
        capability: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Agent]:
        """
        Get agents by capability.

        Args:
            capability: Required capability
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of agents with the capability
        """
        from sqlalchemy import ARRAY
        stmt = select(Agent).where(
            Agent.capabilities.contains([capability])
        )
        stmt = stmt.order_by(desc(Agent.registered_at))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def register_agent(
        self,
        name: str,
        agent_type: AgentType,
        version: Optional[str] = None,
        description: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        endpoint: Optional[str] = None,
    ) -> Agent:
        """
        Register a new agent.

        Args:
            name: Agent name
            agent_type: Agent type
            version: Optional version
            description: Optional description
            capabilities: Optional capabilities list
            config: Optional configuration
            host: Optional host
            port: Optional port
            endpoint: Optional endpoint

        Returns:
            Registered agent
        """
        attributes = {
            "name": name,
            "agent_type": agent_type,
            "version": version,
            "description": description,
            "capabilities": capabilities or [],
            "config": config or {},
            "host": host,
            "port": port,
            "endpoint": endpoint,
            "last_heartbeat": datetime.now(timezone.utc),
        }
        
        existing = await self.get_by_name(name)
        if existing:
            return await self.update(existing.agent_id, attributes)
        
        return await self.create(attributes, commit=True)

    async def unregister_agent(
        self,
        agent_id: int,
    ) -> bool:
        """
        Unregister an agent.

        Args:
            agent_id: Agent ID

        Returns:
            True if unregistered, False if not found
        """
        return await self.update(
            agent_id,
            {
                "status": AgentStatus.STOPPED.value,
                "last_heartbeat": None,
            },
        ) is not None

    async def get_agent_statistics(self) -> Dict[str, Any]:
        """
        Get agent statistics.

        Returns:
            Dictionary with agent statistics
        """
        total_stmt = select(func.count()).select_from(Agent)
        total_result = await self.session.execute(total_stmt)
        total_count = total_result.scalar() or 0
        
        status_stmt = select(
            Agent.status,
            func.count().label("count")
        ).group_by(Agent.status)
        status_result = await self.session.execute(status_stmt)
        status_counts = {row.status: row.count for row in status_result.all()}
        
        type_stmt = select(
            Agent.agent_type,
            func.count().label("count")
        ).group_by(Agent.agent_type)
        type_result = await self.session.execute(type_stmt)
        type_counts = {row.agent_type: row.count for row in type_result.all()}
        
        healthy_stmt = select(func.count()).select_from(Agent).where(
            Agent.status.in_([AgentStatus.IDLE.value, AgentStatus.RUNNING.value, AgentStatus.BUSY.value])
        )
        healthy_result = await self.session.execute(healthy_stmt)
        healthy_count = healthy_result.scalar() or 0
        
        return {
            "total": total_count,
            "healthy": healthy_count,
            "unhealthy": total_count - healthy_count,
            "by_status": status_counts,
            "by_type": type_counts,
        }

    async def increment_task_count(
        self,
        agent_id: int,
        success: bool = True,
    ) -> Optional[Agent]:
        """
        Increment agent task counters.

        Args:
            agent_id: Agent ID
            success: Whether task was successful

        Returns:
            Updated agent or None if not found
        """
        agent = await self.get_by_id(agent_id)
        if agent is None:
            return None
        
        if success:
            agent.tasks_completed += 1
        else:
            agent.tasks_failed += 1
        
        await self.session.commit()
        await self.session.refresh(agent)
        return agent

    async def record_error(
        self,
        agent_id: int,
        error: str,
    ) -> Optional[Agent]:
        """
        Record agent error.

        Args:
            agent_id: Agent ID
            error: Error message

        Returns:
            Updated agent or None if not found
        """
        return await self.update(
            agent_id,
            {
                "last_error": error,
                "last_error_at": datetime.now(timezone.utc),
                "status": AgentStatus.ERROR.value,
            },
        )


class AgentTaskRepository(BaseRepository[AgentTask]):
    """
    Repository for agent task operations.
    """

    def __init__(self, session: AsyncSession) -> None:
        """
        Initialize agent task repository.

        Args:
            session: Async SQLAlchemy session
        """
        super().__init__(session, AgentTask)

    async def get_by_agent(
        self,
        agent_id: int,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AgentTask]:
        """
        Get tasks for an agent.

        Args:
            agent_id: Agent ID
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of agent tasks
        """
        stmt = select(AgentTask).where(AgentTask.agent_id == agent_id)
        stmt = stmt.order_by(desc(AgentTask.created_at))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_status(
        self,
        status: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AgentTask]:
        """
        Get tasks by status.

        Args:
            status: Task status
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of tasks
        """
        stmt = select(AgentTask).where(AgentTask.status == status)
        stmt = stmt.order_by(desc(AgentTask.created_at))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_pending_tasks(
        self,
        limit: int = 100,
    ) -> List[AgentTask]:
        """
        Get pending tasks.

        Args:
            limit: Maximum number of tasks

        Returns:
            List of pending tasks
        """
        return await self.get_by_status("pending", limit=limit)

    async def start_task(
        self,
        task_id: int,
        timeout_at: Optional[datetime] = None,
    ) -> Optional[AgentTask]:
        """
        Mark task as started.

        Args:
            task_id: Task ID
            timeout_at: Optional timeout timestamp

        Returns:
            Updated task or None if not found
        """
        attributes = {
            "status": "running",
            "started_at": datetime.now(timezone.utc),
        }
        if timeout_at:
            attributes["timeout_at"] = timeout_at
        return await self.update(task_id, attributes)

    async def complete_task(
        self,
        task_id: int,
        result: Optional[Dict[str, Any]] = None,
    ) -> Optional[AgentTask]:
        """
        Mark task as completed.

        Args:
            task_id: Task ID
            result: Optional task result

        Returns:
            Updated task or None if not found
        """
        return await self.update(
            task_id,
            {
                "status": "completed",
                "result": result,
                "completed_at": datetime.now(timezone.utc),
            },
        )

    async def fail_task(
        self,
        task_id: int,
        error: str,
    ) -> Optional[AgentTask]:
        """
        Mark task as failed.

        Args:
            task_id: Task ID
            error: Error message

        Returns:
            Updated task or None if not found
        """
        task = await self.get_by_id(task_id)
        if task is None:
            return None
        
        new_retry_count = task.retry_count + 1
        can_retry = new_retry_count < task.max_retries
        
        return await self.update(
            task_id,
            {
                "status": "failed" if not can_retry else "pending",
                "error": error,
                "retry_count": new_retry_count,
                "completed_at": datetime.now(timezone.utc) if not can_retry else None,
            },
        )

    async def get_timed_out_tasks(
        self,
    ) -> List[AgentTask]:
        """
        Get timed out tasks.

        Returns:
            List of timed out tasks
        """
        now = datetime.now(timezone.utc)
        stmt = select(AgentTask).where(
            and_(
                AgentTask.status == "running",
                AgentTask.timeout_at != None,
                AgentTask.timeout_at < now,
            )
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create_task(
        self,
        agent_id: int,
        task_type: str,
        payload: Dict[str, Any],
        timeout_seconds: Optional[int] = None,
    ) -> AgentTask:
        """
        Create a new agent task.

        Args:
            agent_id: Agent ID
            task_type: Task type
            payload: Task payload
            timeout_seconds: Optional timeout in seconds

        Returns:
            Created task
        """
        attributes = {
            "agent_id": agent_id,
            "task_type": task_type,
            "payload": payload,
        }
        
        if timeout_seconds:
            attributes["timeout_at"] = datetime.now(timezone.utc) + timedelta(seconds=timeout_seconds)
        
        return await self.create(attributes, commit=True)
