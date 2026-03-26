from securAIty.api.routes.health import router as health_router
from securAIty.api.routes.auth import router as auth_router
from securAIty.api.routes.events import router as events_router
from securAIty.api.routes.incidents import router as incidents_router
from securAIty.api.routes.agents import router as agents_router

__all__ = [
    "health_router",
    "auth_router",
    "events_router",
    "incidents_router",
    "agents_router",
]
