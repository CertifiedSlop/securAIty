from datetime import datetime, timezone
from typing import Annotated, List
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from securAIty.api.schemas.agents import (
    AgentResponse,
    AgentStatus,
    AgentCapabilities,
    AgentRegister,
    AgentHeartbeat,
    AgentStatusResponse,
)
from securAIty.api.schemas.common import PaginatedResponse, PaginatedRequest, ApiResponse


router = APIRouter(tags=["Agents"])

_agents_store: dict[UUID, AgentResponse] = {}
_agent_heartbeats: dict[UUID, AgentHeartbeat] = {}
HEARTBEAT_TIMEOUT_SECONDS = 60


def parse_pagination(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
) -> PaginatedRequest:
    return PaginatedRequest(page=page, page_size=page_size)


def calculate_health_score(heartbeat: AgentHeartbeat, last_heartbeat: datetime) -> float:
    time_since_heartbeat = (datetime.now(timezone.utc) - last_heartbeat).total_seconds()
    
    if time_since_heartbeat > HEARTBEAT_TIMEOUT_SECONDS * 2:
        return 0.0
    
    time_score = max(0, 100 - (time_since_heartbeat / HEARTBEAT_TIMEOUT_SECONDS * 50))
    
    cpu_score = 100 - (heartbeat.cpu_usage or 0)
    memory_score = 100 - (heartbeat.memory_usage or 0)
    
    task_score = 100
    if heartbeat.active_tasks > 0:
        task_score = max(0, 100 - (heartbeat.failed_tasks / max(1, heartbeat.completed_tasks) * 50))
    
    return round((time_score * 0.4 + cpu_score * 0.2 + memory_score * 0.2 + task_score * 0.2), 2)


@router.get("", response_model=ApiResponse[PaginatedResponse[AgentResponse]])
async def list_agents(
    pagination: Annotated[PaginatedRequest, Depends(parse_pagination)],
    status_filter: AgentStatus | None = Query(default=None, description="Filter by agent status"),
    agent_type: str | None = Query(default=None, description="Filter by agent type"),
) -> ApiResponse[PaginatedResponse[AgentResponse]]:
    items: List[AgentResponse] = list(_agents_store.values())
    
    if status_filter:
        items = [a for a in items if a.status == status_filter]
    
    if agent_type:
        items = [a for a in items if a.agent_type.value == agent_type]
    
    items.sort(key=lambda x: x.registered_at, reverse=True)
    
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
        message=f"Retrieved {len(paginated_items)} agents",
    )


@router.post("", response_model=ApiResponse[AgentResponse], status_code=status.HTTP_201_CREATED)
async def register_agent(agent: AgentRegister) -> ApiResponse[AgentResponse]:
    agent_id = uuid4()
    now = datetime.now(timezone.utc)
    
    agent_response = AgentResponse(
        id=agent_id,
        name=agent.name,
        agent_type=agent.agent_type,
        description=agent.description,
        status=AgentStatus.ONLINE,
        capabilities=agent.capabilities,
        host=agent.host,
        port=agent.port,
        registered_at=now,
        last_heartbeat=now,
    )
    
    _agents_store[agent_id] = agent_response
    
    default_heartbeat = AgentHeartbeat(
        status=AgentStatus.ONLINE,
        cpu_usage=0.0,
        memory_usage=0.0,
        active_tasks=0,
        completed_tasks=0,
        failed_tasks=0,
    )
    _agent_heartbeats[agent_id] = default_heartbeat
    
    return ApiResponse(
        success=True,
        data=agent_response,
        message="Agent registered successfully",
    )


@router.get("/{agent_id}", response_model=ApiResponse[AgentResponse])
async def get_agent(agent_id: UUID) -> ApiResponse[AgentResponse]:
    agent = _agents_store.get(agent_id)
    
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent with id {agent_id} not found",
        )
    
    return ApiResponse(
        success=True,
        data=agent,
        message="Agent retrieved successfully",
    )


@router.get("/{agent_id}/status", response_model=ApiResponse[AgentStatusResponse])
async def get_agent_status(agent_id: UUID) -> ApiResponse[AgentStatusResponse]:
    agent = _agents_store.get(agent_id)
    
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent with id {agent_id} not found",
        )
    
    heartbeat = _agent_heartbeats.get(agent_id)
    
    if not heartbeat:
        heartbeat = AgentHeartbeat(
            status=agent.status,
            cpu_usage=0.0,
            memory_usage=0.0,
            active_tasks=0,
            completed_tasks=0,
            failed_tasks=0,
        )
    
    last_heartbeat = agent.last_heartbeat or agent.registered_at
    time_since_heartbeat = (datetime.now(timezone.utc) - last_heartbeat).total_seconds()
    is_responsive = time_since_heartbeat <= HEARTBEAT_TIMEOUT_SECONDS
    
    health_score = calculate_health_score(heartbeat, last_heartbeat)
    
    status_response = AgentStatusResponse(
        agent_id=agent_id,
        status=agent.status if is_responsive else AgentStatus.OFFLINE,
        last_heartbeat=last_heartbeat,
        cpu_usage=heartbeat.cpu_usage,
        memory_usage=heartbeat.memory_usage,
        active_tasks=heartbeat.active_tasks,
        health_score=health_score,
        is_responsive=is_responsive,
    )
    
    return ApiResponse(
        success=True,
        data=status_response,
        message="Agent status retrieved successfully",
    )


@router.post("/{agent_id}/heartbeat", response_model=ApiResponse[AgentStatusResponse])
async def submit_heartbeat(
    agent_id: UUID,
    heartbeat: AgentHeartbeat,
) -> ApiResponse[AgentStatusResponse]:
    agent = _agents_store.get(agent_id)
    
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent with id {agent_id} not found",
        )
    
    now = datetime.now(timezone.utc)
    agent.last_heartbeat = now
    agent.status = heartbeat.status
    _agents_store[agent_id] = agent
    
    _agent_heartbeats[agent_id] = heartbeat
    
    health_score = calculate_health_score(heartbeat, now)
    is_responsive = True
    
    status_response = AgentStatusResponse(
        agent_id=agent_id,
        status=heartbeat.status,
        last_heartbeat=now,
        cpu_usage=heartbeat.cpu_usage,
        memory_usage=heartbeat.memory_usage,
        active_tasks=heartbeat.active_tasks,
        health_score=health_score,
        is_responsive=is_responsive,
    )
    
    return ApiResponse(
        success=True,
        data=status_response,
        message="Heartbeat received",
    )


@router.delete("/{agent_id}", response_model=ApiResponse[None])
async def deregister_agent(agent_id: UUID) -> ApiResponse[None]:
    if agent_id not in _agents_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent with id {agent_id} not found",
        )
    
    del _agents_store[agent_id]
    
    if agent_id in _agent_heartbeats:
        del _agent_heartbeats[agent_id]
    
    return ApiResponse(
        success=True,
        data=None,
        message="Agent deregistered successfully",
    )
