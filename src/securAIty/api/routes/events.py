from datetime import datetime, timezone
from typing import Annotated, List
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from securAIty.api.schemas.events import EventCreate, EventResponse, EventFilter, EventUpdate
from securAIty.api.schemas.common import PaginatedResponse, PaginatedRequest, ApiResponse


router = APIRouter(tags=["Events"])

_events_store: dict[UUID, EventResponse] = {}


def parse_pagination(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
) -> PaginatedRequest:
    return PaginatedRequest(page=page, page_size=page_size)


@router.get("", response_model=ApiResponse[PaginatedResponse[EventResponse]])
async def list_events(
    pagination: Annotated[PaginatedRequest, Depends(parse_pagination)],
    event_filter: Annotated[EventFilter, Depends()],
) -> ApiResponse[PaginatedResponse[EventResponse]]:
    items: List[EventResponse] = list(_events_store.values())
    
    if event_filter.event_type:
        items = [e for e in items if e.event_type == event_filter.event_type]
    
    if event_filter.severity:
        items = [e for e in items if e.severity == event_filter.severity]
    
    if event_filter.source:
        items = [e for e in items if event_filter.source.lower() in e.source.lower()]
    
    if event_filter.status:
        items = [e for e in items if e.status == event_filter.status]
    
    if event_filter.start_date:
        items = [e for e in items if e.occurred_at >= event_filter.start_date]
    
    if event_filter.end_date:
        items = [e for e in items if e.occurred_at <= event_filter.end_date]
    
    if event_filter.search:
        search_lower = event_filter.search.lower()
        items = [
            e for e in items
            if search_lower in e.title.lower() or search_lower in e.description.lower()
        ]
    
    items.sort(key=lambda x: x.occurred_at, reverse=True)
    
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
        message=f"Retrieved {len(paginated_items)} events",
    )


@router.post("", response_model=ApiResponse[EventResponse], status_code=status.HTTP_201_CREATED)
async def create_event(event: EventCreate) -> ApiResponse[EventResponse]:
    event_id = uuid4()
    now = datetime.now(timezone.utc)
    
    event_response = EventResponse(
        id=event_id,
        event_type=event.event_type,
        severity=event.severity,
        source=event.source,
        title=event.title,
        description=event.description,
        status="new",
        occurred_at=event.occurred_at or now,
        created_at=now,
        updated_at=None,
        metadata=event.metadata,
        related_incident_id=None,
    )
    
    _events_store[event_id] = event_response
    
    return ApiResponse(
        success=True,
        data=event_response,
        message="Event created successfully",
    )


@router.get("/{event_id}", response_model=ApiResponse[EventResponse])
async def get_event(event_id: UUID) -> ApiResponse[EventResponse]:
    event = _events_store.get(event_id)
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with id {event_id} not found",
        )
    
    return ApiResponse(
        success=True,
        data=event,
        message="Event retrieved successfully",
    )


@router.patch("/{event_id}", response_model=ApiResponse[EventResponse])
async def update_event(event_id: UUID, event_update: EventUpdate) -> ApiResponse[EventResponse]:
    event = _events_store.get(event_id)
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with id {event_id} not found",
        )
    
    update_data = event_update.model_dump(exclude_unset=True)
    
    for field, value in update_data.items():
        if value is not None:
            setattr(event, field, value)
    
    event.updated_at = datetime.now(timezone.utc)
    _events_store[event_id] = event
    
    return ApiResponse(
        success=True,
        data=event,
        message="Event updated successfully",
    )


@router.delete("/{event_id}", response_model=ApiResponse[None])
async def delete_event(event_id: UUID) -> ApiResponse[None]:
    if event_id not in _events_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with id {event_id} not found",
        )
    
    del _events_store[event_id]
    
    return ApiResponse(
        success=True,
        data=None,
        message="Event deleted successfully",
    )
