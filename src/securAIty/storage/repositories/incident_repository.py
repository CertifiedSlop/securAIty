"""
Incident Repository

Repository for incident operations with specialized queries.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from securAIty.storage.models import Incident, IncidentStatus, IncidentSeverity, IncidentNote
from securAIty.storage.repositories.base import BaseRepository


class IncidentRepository(BaseRepository[Incident]):
    """
    Repository for incident operations.

    Provides specialized queries and operations for security incidents.
    """

    def __init__(self, session: AsyncSession) -> None:
        """
        Initialize incident repository.

        Args:
            session: Async SQLAlchemy session
        """
        super().__init__(session, Incident)

    async def get_by_status(
        self,
        status: IncidentStatus,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Incident]:
        """
        Get incidents by status.

        Args:
            status: Incident status enum
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching incidents
        """
        stmt = select(Incident).where(Incident.status == status.value)
        stmt = stmt.order_by(desc(Incident.detected_at))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_severity(
        self,
        severity: IncidentSeverity,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Incident]:
        """
        Get incidents by severity.

        Args:
            severity: Incident severity enum
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching incidents
        """
        stmt = select(Incident).where(Incident.severity == severity.value)
        stmt = stmt.order_by(desc(Incident.detected_at))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_open_incidents(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Incident]:
        """
        Get all open incidents.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of open incidents
        """
        return await self.get_by_status(IncidentStatus.OPEN, skip, limit)

    async def get_assigned_to(
        self,
        assignee: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Incident]:
        """
        Get incidents assigned to a user.

        Args:
            assignee: Assignee identifier
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of assigned incidents
        """
        stmt = select(Incident).where(Incident.assigned_to == assignee)
        stmt = stmt.order_by(desc(Incident.detected_at))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def assign_incident(
        self,
        incident_id: int,
        assignee: str,
    ) -> Optional[Incident]:
        """
        Assign incident to a user.

        Args:
            incident_id: Incident ID
            assignee: Assignee identifier

        Returns:
            Updated incident or None if not found
        """
        return await self.update(
            incident_id,
            {
                "assigned_to": assignee,
                "acknowledged_at": datetime.now(timezone.utc),
            },
        )

    async def update_status(
        self,
        incident_id: int,
        status: IncidentStatus,
        add_timeline_entry: Optional[str] = None,
    ) -> Optional[Incident]:
        """
        Update incident status.

        Args:
            incident_id: Incident ID
            status: New status
            add_timeline_entry: Optional timeline entry

        Returns:
            Updated incident or None if not found
        """
        attributes = {"status": status.value}
        
        now = datetime.now(timezone.utc)
        if status == IncidentStatus.CONTAINED:
            attributes["contained_at"] = now
        elif status == IncidentStatus.RESOLVED:
            attributes["resolved_at"] = now
        elif status == IncidentStatus.CLOSED:
            attributes["closed_at"] = now
        
        incident = await self.get_by_id(incident_id)
        if incident and add_timeline_entry:
            incident.add_timeline_entry(add_timeline_entry, "status_change")
        
        return await self.update(incident_id, attributes)

    async def add_timeline_entry(
        self,
        incident_id: int,
        entry: str,
        entry_type: str = "note",
    ) -> Optional[Incident]:
        """
        Add timeline entry to incident.

        Args:
            incident_id: Incident ID
            entry: Timeline entry content
            entry_type: Entry type

        Returns:
            Updated incident or None if not found
        """
        incident = await self.get_by_id(incident_id)
        if incident is None:
            return None
        
        incident.add_timeline_entry(entry, entry_type)
        await self.session.commit()
        await self.session.refresh(incident)
        return incident

    async def get_by_external_id(
        self,
        external_id: str,
    ) -> Optional[Incident]:
        """
        Get incident by external ID.

        Args:
            external_id: External incident ID

        Returns:
            Incident or None if not found
        """
        return await self.get_first({"external_id": external_id})

    async def get_by_tags(
        self,
        tags: List[str],
        skip: int = 0,
        limit: int = 100,
    ) -> List[Incident]:
        """
        Get incidents by tags.

        Args:
            tags: List of tags to match
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of matching incidents
        """
        from sqlalchemy import ARRAY
        stmt = select(Incident).where(
            Incident.tags.overlap(tags)
        )
        stmt = stmt.order_by(desc(Incident.detected_at))
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_incident_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get incident statistics.

        Args:
            start_time: Optional start time filter
            end_time: Optional end time filter

        Returns:
            Dictionary with incident statistics
        """
        base_query = select(Incident)
        if start_time:
            base_query = base_query.where(Incident.detected_at >= start_time)
        if end_time:
            base_query = base_query.where(Incident.detected_at <= end_time)
        
        total_stmt = select(func.count()).select_from(Incident)
        if start_time:
            total_stmt = total_stmt.where(Incident.detected_at >= start_time)
        if end_time:
            total_stmt = total_stmt.where(Incident.detected_at <= end_time)
        
        total_result = await self.session.execute(total_stmt)
        total_count = total_result.scalar() or 0
        
        status_stmt = select(
            Incident.status,
            func.count().label("count")
        )
        if start_time:
            status_stmt = status_stmt.where(Incident.detected_at >= start_time)
        if end_time:
            status_stmt = status_stmt.where(Incident.detected_at <= end_time)
        status_stmt = status_stmt.group_by(Incident.status)
        status_result = await self.session.execute(status_stmt)
        status_counts = {row.status: row.count for row in status_result.all()}
        
        severity_stmt = select(
            Incident.severity,
            func.count().label("count")
        )
        if start_time:
            severity_stmt = severity_stmt.where(Incident.detected_at >= start_time)
        if end_time:
            severity_stmt = severity_stmt.where(Incident.detected_at <= end_time)
        severity_stmt = severity_stmt.group_by(Incident.severity)
        severity_result = await self.session.execute(severity_stmt)
        severity_counts = {row.severity: row.count for row in severity_result.all()}
        
        return {
            "total": total_count,
            "by_status": status_counts,
            "by_severity": severity_counts,
        }

    async def create_incident(
        self,
        title: str,
        severity: IncidentSeverity,
        description: Optional[str] = None,
        priority: Optional[str] = None,
        assigned_to: Optional[str] = None,
        related_event_ids: Optional[List[int]] = None,
        tags: Optional[List[str]] = None,
        external_id: Optional[str] = None,
        source_system: Optional[str] = None,
    ) -> Incident:
        """
        Create a new incident.

        Args:
            title: Incident title
            severity: Incident severity
            description: Optional description
            priority: Optional priority
            assigned_to: Optional assignee
            related_event_ids: Optional related event IDs
            tags: Optional tags
            external_id: Optional external ID
            source_system: Optional source system

        Returns:
            Created incident
        """
        attributes = {
            "title": title,
            "severity": severity,
            "description": description,
            "priority": priority,
            "assigned_to": assigned_to,
            "related_event_ids": related_event_ids or [],
            "tags": tags or [],
            "external_id": external_id,
            "source_system": source_system,
        }
        incident = await self.create(attributes, commit=True)
        incident.add_timeline_entry("Incident created", "system")
        await self.session.commit()
        await self.session.refresh(incident)
        return incident


class IncidentNoteRepository(BaseRepository[IncidentNote]):
    """
    Repository for incident note operations.
    """

    def __init__(self, session: AsyncSession) -> None:
        """
        Initialize incident note repository.

        Args:
            session: Async SQLAlchemy session
        """
        super().__init__(session, IncidentNote)

    async def get_by_incident(
        self,
        incident_id: int,
        skip: int = 0,
        limit: int = 100,
    ) -> List[IncidentNote]:
        """
        Get notes for an incident.

        Args:
            incident_id: Incident ID
            skip: Number of records to skip
            limit: Maximum number of records

        Returns:
            List of incident notes
        """
        stmt = select(IncidentNote).where(IncidentNote.incident_id == incident_id)
        stmt = stmt.order_by(IncidentNote.created_at)
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create_note(
        self,
        incident_id: int,
        content: str,
        author: str,
        is_internal: bool = True,
    ) -> IncidentNote:
        """
        Create a new incident note.

        Args:
            incident_id: Incident ID
            content: Note content
            author: Note author
            is_internal: Whether note is internal

        Returns:
            Created note
        """
        attributes = {
            "incident_id": incident_id,
            "content": content,
            "author": author,
            "is_internal": is_internal,
        }
        return await self.create(attributes, commit=True)
