from datetime import datetime, timezone
from typing import Annotated, List
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from securAIty.api.schemas.incidents import (
    IncidentCreate,
    IncidentResponse,
    IncidentUpdate,
    IncidentFilter,
    IncidentStatus,
)
from securAIty.api.schemas.common import PaginatedResponse, PaginatedRequest, ApiResponse


router = APIRouter(tags=["Incidents"])

_incidents_store: dict[UUID, IncidentResponse] = {}


def parse_pagination(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
) -> PaginatedRequest:
    return PaginatedRequest(page=page, page_size=page_size)


@router.get("", response_model=ApiResponse[PaginatedResponse[IncidentResponse]])
async def list_incidents(
    pagination: Annotated[PaginatedRequest, Depends(parse_pagination)],
    incident_filter: Annotated[IncidentFilter, Depends()],
) -> ApiResponse[PaginatedResponse[IncidentResponse]]:
    items: List[IncidentResponse] = list(_incidents_store.values())
    
    if incident_filter.status:
        items = [i for i in items if i.status == incident_filter.status]
    
    if incident_filter.priority:
        items = [i for i in items if i.priority == incident_filter.priority]
    
    if incident_filter.category:
        items = [i for i in items if i.category == incident_filter.category]
    
    if incident_filter.assigned_to:
        items = [i for i in items if i.assigned_to == incident_filter.assigned_to]
    
    if incident_filter.search:
        search_lower = incident_filter.search.lower()
        items = [
            i for i in items
            if search_lower in i.title.lower() or search_lower in i.description.lower()
        ]
    
    if incident_filter.start_date:
        items = [i for i in items if i.created_at >= incident_filter.start_date]
    
    if incident_filter.end_date:
        items = [i for i in items if i.created_at <= incident_filter.end_date]
    
    items.sort(key=lambda x: x.created_at, reverse=True)
    
    total = len(items)
    start_idx = (pagination.page - 1) * pagination.page_size
    end_idx = start_idx + pagination.page_size
    paginated_items = items[start_idx:end_idx]
    
    paginated_response = PaginatedResponse.create(
        items=paginated_items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
    )
    
    return ApiResponse(
        success=True,
        data=paginated_response,
        message=f"Retrieved {len(paginated_items)} incidents",
    )


@router.post("", response_model=ApiResponse[IncidentResponse], status_code=status.HTTP_201_CREATED)
async def create_incident(incident: IncidentCreate) -> ApiResponse[IncidentResponse]:
    incident_id = uuid4()
    now = datetime.now(timezone.utc)
    
    incident_response = IncidentResponse(
        id=incident_id,
        title=incident.title,
        description=incident.description,
        category=incident.category,
        priority=incident.priority,
        status=incident.status,
        assigned_to=incident.assigned_to,
        related_event_ids=incident.related_event_ids or [],
        created_at=now,
        updated_at=None,
        resolved_at=None,
        resolution_notes=None,
        metadata=incident.metadata,
    )
    
    _incidents_store[incident_id] = incident_response
    
    return ApiResponse(
        success=True,
        data=incident_response,
        message="Incident created successfully",
    )


@router.get("/{incident_id}", response_model=ApiResponse[IncidentResponse])
async def get_incident(incident_id: UUID) -> ApiResponse[IncidentResponse]:
    incident = _incidents_store.get(incident_id)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id {incident_id} not found",
        )
    
    return ApiResponse(
        success=True,
        data=incident,
        message="Incident retrieved successfully",
    )


@router.patch("/{incident_id}", response_model=ApiResponse[IncidentResponse])
async def update_incident(
    incident_id: UUID,
    incident_update: IncidentUpdate,
) -> ApiResponse[IncidentResponse]:
    incident = _incidents_store.get(incident_id)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id {incident_id} not found",
        )
    
    update_data = incident_update.model_dump(exclude_unset=True)
    now = datetime.now(timezone.utc)
    
    for field, value in update_data.items():
        if value is not None:
            setattr(incident, field, value)
            
            if field == "status" and value == IncidentStatus.RESOLVED:
                incident.resolved_at = now
    
    incident.updated_at = now
    _incidents_store[incident_id] = incident
    
    return ApiResponse(
        success=True,
        data=incident,
        message="Incident updated successfully",
    )


@router.delete("/{incident_id}", response_model=ApiResponse[None])
async def delete_incident(incident_id: UUID) -> ApiResponse[None]:
    if incident_id not in _incidents_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id {incident_id} not found",
        )
    
    del _incidents_store[incident_id]
    
    return ApiResponse(
        success=True,
        data=None,
        message="Incident deleted successfully",
    )
