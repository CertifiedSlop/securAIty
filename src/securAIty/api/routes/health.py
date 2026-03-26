from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends

from securAIty.api.schemas.common import ApiResponse


router = APIRouter(tags=["Health"])


def get_health_status() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "version": "0.1.0",
        "services": {
            "api": "operational",
            "database": "unknown",
            "nats": "unknown",
            "vault": "unknown",
        },
    }


def get_readiness_status() -> Dict[str, Any]:
    return {
        "ready": True,
        "timestamp": datetime.utcnow(),
        "checks": {
            "database_connection": True,
            "nats_connection": True,
            "vault_connection": True,
            "agents_connected": True,
        },
    }


@router.get("/health")
async def health_check() -> ApiResponse[Dict[str, Any]]:
    status = get_health_status()
    return ApiResponse(
        success=True,
        data=status,
        message="Service is healthy",
    )


@router.get("/ready")
async def readiness_check() -> ApiResponse[Dict[str, Any]]:
    status = get_readiness_status()
    return ApiResponse(
        success=status["ready"],
        data=status,
        message="Service is ready" if status["ready"] else "Service is not ready",
    )
