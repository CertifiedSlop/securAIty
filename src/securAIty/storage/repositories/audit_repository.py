"""
Audit Repository

Repository for audit log operations with specialized queries.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from securAIty.storage.models import AuditLog, ActionType, AuditStatus
from securAIty.storage.repositories.base import BaseRepository


class AuditRepository(BaseRepository[AuditLog]):
    """
    Repository for audit log operations.

    Provides specialized queries and operations for audit logs.
    """

    def __init__(self, session: AsyncSession) -> None:
        """
        Initialize audit repository.

        Args:
            session: Async SQLAlchemy session
        """
        super().__init__(session, AuditLog)

    async def get_by_actor(
        self,
        actor: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get audit logs by actor.

        Args:
            actor: Actor identifier
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of audit logs
        """
        stmt = select(AuditLog).where(AuditLog.actor == actor)
        stmt = stmt.order_by(desc(AuditLog.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_action(
        self,
        action: ActionType,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get audit logs by action type.

        Args:
            action: Action type enum
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of audit logs
        """
        stmt = select(AuditLog).where(AuditLog.action == action.value)
        stmt = stmt.order_by(desc(AuditLog.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_resource(
        self,
        resource_type: str,
        resource_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get audit logs by resource.

        Args:
            resource_type: Resource type
            resource_id: Optional resource ID
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of audit logs
        """
        stmt = select(AuditLog).where(AuditLog.resource_type == resource_type)
        
        if resource_id:
            stmt = stmt.where(AuditLog.resource_id == resource_id)
        
        stmt = stmt.order_by(desc(AuditLog.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_time_range(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get audit logs within time range.

        Args:
            start_time: Start of time range
            end_time: End of time range (defaults to now)
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of audit logs
        """
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        
        stmt = select(AuditLog).where(
            and_(
                AuditLog.timestamp >= start_time,
                AuditLog.timestamp <= end_time,
            )
        )
        stmt = stmt.order_by(desc(AuditLog.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_failed_actions(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get failed audit actions.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of failed audit logs
        """
        stmt = select(AuditLog).where(AuditLog.status == AuditStatus.FAILURE.value)
        stmt = stmt.order_by(desc(AuditLog.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_session(
        self,
        session_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get audit logs by session ID.

        Args:
            session_id: Session identifier
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of audit logs
        """
        stmt = select(AuditLog).where(AuditLog.session_id == session_id)
        stmt = stmt.order_by(AuditLog.timestamp)
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_request(
        self,
        request_id: str,
    ) -> List[AuditLog]:
        """
        Get audit logs by request ID.

        Args:
            request_id: Request identifier

        Returns:
            List of audit logs
        """
        stmt = select(AuditLog).where(AuditLog.request_id == request_id)
        stmt = stmt.order_by(AuditLog.timestamp)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_tenant(
        self,
        tenant_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get audit logs by tenant ID.

        Args:
            tenant_id: Tenant identifier
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of audit logs
        """
        stmt = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
        stmt = stmt.order_by(desc(AuditLog.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_recent_activity(
        self,
        actor: str,
        minutes: int = 60,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get recent activity for an actor.

        Args:
            actor: Actor identifier
            minutes: Number of minutes to look back
            limit: Maximum number of records

        Returns:
            List of recent audit logs
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        stmt = select(AuditLog).where(
            and_(
                AuditLog.actor == actor,
                AuditLog.timestamp >= cutoff,
            )
        )
        stmt = stmt.order_by(desc(AuditLog.timestamp))
        stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_audit_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get audit statistics.

        Args:
            start_time: Optional start time filter
            end_time: Optional end time filter
            actor: Optional actor filter

        Returns:
            Dictionary with audit statistics
        """
        base_query = select(AuditLog)
        if start_time:
            base_query = base_query.where(AuditLog.timestamp >= start_time)
        if end_time:
            base_query = base_query.where(AuditLog.timestamp <= end_time)
        if actor:
            base_query = base_query.where(AuditLog.actor == actor)
        
        total_stmt = select(func.count()).select_from(AuditLog)
        if start_time:
            total_stmt = total_stmt.where(AuditLog.timestamp >= start_time)
        if end_time:
            total_stmt = total_stmt.where(AuditLog.timestamp <= end_time)
        if actor:
            total_stmt = total_stmt.where(AuditLog.actor == actor)
        
        total_result = await self.session.execute(total_stmt)
        total_count = total_result.scalar() or 0
        
        action_stmt = select(
            AuditLog.action,
            func.count().label("count")
        )
        if start_time:
            action_stmt = action_stmt.where(AuditLog.timestamp >= start_time)
        if end_time:
            action_stmt = action_stmt.where(AuditLog.timestamp <= end_time)
        if actor:
            action_stmt = action_stmt.where(AuditLog.actor == actor)
        action_stmt = action_stmt.group_by(AuditLog.action)
        action_result = await self.session.execute(action_stmt)
        action_counts = {row.action: row.count for row in action_result.all()}
        
        status_stmt = select(
            AuditLog.status,
            func.count().label("count")
        )
        if start_time:
            status_stmt = status_stmt.where(AuditLog.timestamp >= start_time)
        if end_time:
            status_stmt = status_stmt.where(AuditLog.timestamp <= end_time)
        if actor:
            status_stmt = status_stmt.where(AuditLog.actor == actor)
        status_stmt = status_stmt.group_by(AuditLog.status)
        status_result = await self.session.execute(status_stmt)
        status_counts = {row.status: row.count for row in status_result.all()}
        
        resource_stmt = select(
            AuditLog.resource_type,
            func.count().label("count")
        )
        if start_time:
            resource_stmt = resource_stmt.where(AuditLog.timestamp >= start_time)
        if end_time:
            resource_stmt = resource_stmt.where(AuditLog.timestamp <= end_time)
        if actor:
            resource_stmt = resource_stmt.where(AuditLog.actor == actor)
        resource_stmt = resource_stmt.group_by(AuditLog.resource_type)
        resource_result = await self.session.execute(resource_stmt)
        resource_counts = {row.resource_type: row.count for row in resource_result.all()}
        
        return {
            "total": total_count,
            "by_action": action_counts,
            "by_status": status_counts,
            "by_resource_type": resource_counts,
        }

    async def create_audit_log(
        self,
        action: ActionType,
        actor: str,
        resource_type: str,
        status: AuditStatus = AuditStatus.SUCCESS,
        resource_id: Optional[str] = None,
        resource_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        changes: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        duration_ms: Optional[int] = None,
        actor_type: str = "user",
    ) -> AuditLog:
        """
        Create a new audit log entry.

        Args:
            action: Action type
            actor: Actor identifier
            resource_type: Resource type
            status: Action status
            resource_id: Optional resource ID
            resource_name: Optional resource name
            details: Optional details dictionary
            changes: Optional changes dictionary
            reason: Optional reason
            ip_address: Optional IP address
            user_agent: Optional user agent
            session_id: Optional session ID
            request_id: Optional request ID
            tenant_id: Optional tenant ID
            duration_ms: Optional duration in milliseconds
            actor_type: Type of actor (user, system, agent)

        Returns:
            Created audit log
        """
        attributes = {
            "action": action,
            "actor": actor,
            "actor_type": actor_type,
            "resource_type": resource_type,
            "status": status,
            "resource_id": resource_id,
            "resource_name": resource_name,
            "details": details or {},
            "changes": changes,
            "reason": reason,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "session_id": session_id,
            "request_id": request_id,
            "tenant_id": tenant_id,
            "duration_ms": duration_ms,
        }
        return await self.create(attributes, commit=True)

    async def log_action(
        self,
        action: str,
        actor: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AuditLog:
        """
        Convenience method to log an action.

        Args:
            action: Action name
            actor: Actor identifier
            resource_type: Resource type
            resource_id: Optional resource ID
            success: Whether action succeeded
            details: Optional details
            **kwargs: Additional attributes

        Returns:
            Created audit log
        """
        action_enum = ActionType(action) if action in [e.value for e in ActionType] else ActionType.CUSTOM
        status = AuditStatus.SUCCESS if success else AuditStatus.FAILURE
        
        attributes = {
            "action": action_enum,
            "actor": actor,
            "resource_type": resource_type,
            "status": status,
            "resource_id": resource_id,
            "details": details or {},
        }
        attributes.update(kwargs)
        
        return await self.create(attributes, commit=True)
