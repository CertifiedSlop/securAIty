"""
Event Repository

Repository for security event operations with specialized queries.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from securAIty.storage.models import SecurityEvent, EventType, SeverityLevel
from securAIty.storage.repositories.base import BaseRepository


class EventRepository(BaseRepository[SecurityEvent]):
    """
    Repository for security event operations.

    Provides specialized queries and operations for security events.
    """

    def __init__(self, session: AsyncSession) -> None:
        """
        Initialize event repository.

        Args:
            session: Async SQLAlchemy session
        """
        super().__init__(session, SecurityEvent)

    async def get_by_event_type(
        self,
        event_type: EventType,
        skip: int = 0,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        Get events by event type.

        Args:
            event_type: Event type enum
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching events
        """
        stmt = select(SecurityEvent).where(SecurityEvent.event_type == event_type.value)
        stmt = stmt.order_by(desc(SecurityEvent.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_severity(
        self,
        severity: SeverityLevel,
        skip: int = 0,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        Get events by severity level.

        Args:
            severity: Severity level enum
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching events
        """
        stmt = select(SecurityEvent).where(SecurityEvent.severity == severity.value)
        stmt = stmt.order_by(desc(SecurityEvent.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_time_range(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        Get events within time range.

        Args:
            start_time: Start of time range
            end_time: End of time range (defaults to now)
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching events
        """
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        
        stmt = select(SecurityEvent).where(
            and_(
                SecurityEvent.timestamp >= start_time,
                SecurityEvent.timestamp <= end_time,
            )
        )
        stmt = stmt.order_by(desc(SecurityEvent.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_unprocessed_events(
        self,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        Get unprocessed events.

        Args:
            limit: Maximum number of events

        Returns:
            List of unprocessed events
        """
        stmt = select(SecurityEvent).where(SecurityEvent.processed == False)
        stmt = stmt.order_by(SecurityEvent.timestamp)
        stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def mark_as_processed(self, event_ids: List[int]) -> int:
        """
        Mark events as processed.

        Args:
            event_ids: List of event IDs to mark

        Returns:
            Number of events marked
        """
        from sqlalchemy import update
        stmt = update(SecurityEvent).where(
            SecurityEvent.event_id.in_(event_ids)
        ).values(processed=True)
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount or 0

    async def get_by_actor(
        self,
        actor_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        Get events by actor.

        Args:
            actor_id: Actor identifier
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of events for the actor
        """
        stmt = select(SecurityEvent).where(SecurityEvent.actor_id == actor_id)
        stmt = stmt.order_by(desc(SecurityEvent.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_correlation_id(
        self,
        correlation_id: str,
    ) -> List[SecurityEvent]:
        """
        Get events by correlation ID.

        Args:
            correlation_id: Correlation ID

        Returns:
            List of correlated events
        """
        stmt = select(SecurityEvent).where(
            SecurityEvent.correlation_id == correlation_id
        )
        stmt = stmt.order_by(SecurityEvent.timestamp)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_recent_events(
        self,
        minutes: int = 60,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        Get recent events.

        Args:
            minutes: Number of minutes to look back
            limit: Maximum number of events

        Returns:
            List of recent events
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        stmt = select(SecurityEvent).where(SecurityEvent.timestamp >= cutoff)
        stmt = stmt.order_by(desc(SecurityEvent.timestamp))
        stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_events_by_source(
        self,
        source: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        Get events by source.

        Args:
            source: Event source identifier
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of events from the source
        """
        stmt = select(SecurityEvent).where(SecurityEvent.source == source)
        stmt = stmt.order_by(desc(SecurityEvent.timestamp))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_critical_events(
        self,
        unprocessed_only: bool = False,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        Get critical severity events.

        Args:
            unprocessed_only: Only return unprocessed events
            limit: Maximum number of events

        Returns:
            List of critical events
        """
        stmt = select(SecurityEvent).where(
            SecurityEvent.severity == SeverityLevel.CRITICAL.value
        )
        if unprocessed_only:
            stmt = stmt.where(SecurityEvent.processed == False)
        stmt = stmt.order_by(desc(SecurityEvent.timestamp))
        stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_event_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get event statistics.

        Args:
            start_time: Optional start time filter
            end_time: Optional end time filter

        Returns:
            Dictionary with event statistics
        """
        from sqlalchemy import case
        
        base_query = select(SecurityEvent)
        if start_time:
            base_query = base_query.where(SecurityEvent.timestamp >= start_time)
        if end_time:
            base_query = base_query.where(SecurityEvent.timestamp <= end_time)
        
        total_stmt = select(func.count()).select_from(SecurityEvent)
        if start_time:
            total_stmt = total_stmt.where(SecurityEvent.timestamp >= start_time)
        if end_time:
            total_stmt = total_stmt.where(SecurityEvent.timestamp <= end_time)
        
        total_result = await self.session.execute(total_stmt)
        total_count = total_result.scalar() or 0
        
        severity_stmt = select(
            SecurityEvent.severity,
            func.count().label("count")
        )
        if start_time:
            severity_stmt = severity_stmt.where(SecurityEvent.timestamp >= start_time)
        if end_time:
            severity_stmt = severity_stmt.where(SecurityEvent.timestamp <= end_time)
        severity_stmt = severity_stmt.group_by(SecurityEvent.severity)
        severity_result = await self.session.execute(severity_stmt)
        severity_counts = {row.severity: row.count for row in severity_result.all()}
        
        event_type_stmt = select(
            SecurityEvent.event_type,
            func.count().label("count")
        )
        if start_time:
            event_type_stmt = event_type_stmt.where(SecurityEvent.timestamp >= start_time)
        if end_time:
            event_type_stmt = event_type_stmt.where(SecurityEvent.timestamp <= end_time)
        event_type_stmt = event_type_stmt.group_by(SecurityEvent.event_type)
        event_type_result = await self.session.execute(event_type_stmt)
        event_type_counts = {row.event_type: row.count for row in event_type_result.all()}
        
        return {
            "total": total_count,
            "by_severity": severity_counts,
            "by_event_type": event_type_counts,
        }

    async def create_event(
        self,
        event_type: EventType,
        severity: SeverityLevel,
        source: str,
        payload: Dict[str, Any],
        title: Optional[str] = None,
        description: Optional[str] = None,
        actor_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> SecurityEvent:
        """
        Create a new security event.

        Args:
            event_type: Type of event
            severity: Severity level
            source: Event source
            payload: Event payload data
            title: Optional event title
            description: Optional event description
            actor_id: Optional actor identifier
            correlation_id: Optional correlation ID
            ip_address: Optional IP address

        Returns:
            Created security event
        """
        attributes = {
            "event_type": event_type,
            "severity": severity,
            "source": source,
            "payload": payload,
            "title": title,
            "description": description,
            "actor_id": actor_id,
            "correlation_id": correlation_id,
            "ip_address": ip_address,
        }
        return await self.create(attributes, commit=True)
