from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from securAIty.api.middleware.authentication import HTTPException
from securAIty.api.schemas.common import ErrorResponse


def create_exception_handler(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        error_response = ErrorResponse(
            error_code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
            details={"status_code": exc.status_code},
            path=request.url.path,
            timestamp=datetime.utcnow(),
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content=error_response.model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        errors = []
        for error in exc.errors():
            errors.append({
                "field": ".".join(str(x) for x in error.get("loc", [])),
                "message": error.get("msg", ""),
                "type": error.get("type", ""),
            })
        
        error_response = ErrorResponse(
            error_code="VALIDATION_ERROR",
            message="Request validation failed",
            details={"errors": errors},
            path=request.url.path,
            timestamp=datetime.utcnow(),
        )
        
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=error_response.model_dump(),
        )

    @app.exception_handler(HTTPException)
    async def fastapi_http_exception_handler(
        request: Request,
        exc: HTTPException,
    ) -> JSONResponse:
        error_response = ErrorResponse(
            error_code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
            details={"headers": exc.headers} if exc.headers else None,
            path=request.url.path,
            timestamp=datetime.utcnow(),
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content=error_response.model_dump(),
            headers=exc.headers or {},
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        error_response = ErrorResponse(
            error_code="INTERNAL_SERVER_ERROR",
            message="An unexpected error occurred",
            details={"error_type": type(exc).__name__},
            path=request.url.path,
            timestamp=datetime.utcnow(),
        )
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.model_dump(),
        )


def create_application() -> FastAPI:
    import os
    
    app_name = os.getenv("APP_NAME", "securAIty")
    debug = os.getenv("DEBUG", "false").lower() == "true"
    api_prefix = os.getenv("API_PREFIX", "/api/v1")
    
    app = FastAPI(
        title=app_name,
        description="AI-powered security orchestration platform with NATS messaging, PostgreSQL storage, and Vault secrets management",
        version="0.1.0",
        docs_url="/docs" if debug else None,
        redoc_url="/redoc" if debug else None,
        openapi_url="/openapi.json" if debug else None,
        debug=debug,
    )
    
    return app


def register_routers(app: FastAPI) -> None:
    from securAIty.api.routes.health import router as health_router
    from securAIty.api.routes.auth import router as auth_router
    from securAIty.api.routes.events import router as events_router
    from securAIty.api.routes.incidents import router as incidents_router
    from securAIty.api.routes.agents import router as agents_router
    
    api_prefix = os.getenv("API_PREFIX", "/api/v1")
    
    app.include_router(health_router, prefix=f"{api_prefix}")
    app.include_router(auth_router, prefix=f"{api_prefix}/auth")
    app.include_router(events_router, prefix=f"{api_prefix}/events")
    app.include_router(incidents_router, prefix=f"{api_prefix}/incidents")
    app.include_router(agents_router, prefix=f"{api_prefix}/agents")


def register_middleware(app: FastAPI) -> None:
    from securAIty.api.middleware.cors import setup_cors_middleware
    from securAIty.api.middleware.rate_limit import RateLimitMiddleware, RateLimitConfig
    from securAIty.api.middleware.logging import RequestLoggingMiddleware, setup_structured_logging
    import os
    
    setup_structured_logging(
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_format="json" if os.getenv("APP_ENV", "development") == "production" else "text",
    )
    
    setup_cors_middleware(app)
    
    rate_config = RateLimitConfig.from_env()
    app.add_middleware(
        RateLimitMiddleware,
        config=rate_config,
        excluded_paths=["/health", "/ready", "/docs", "/openapi.json", "/redoc"],
    )
    
    app.add_middleware(
        RequestLoggingMiddleware,
        include_body=False,
        include_response_body=False,
        log_level=os.getenv("LOG_LEVEL", "INFO"),
    )


def register_startup_events(app: FastAPI) -> None:
    @app.on_event("startup")
    async def startup_event() -> None:
        import os
        from securAIty.logging import get_logger
        
        logger = get_logger(__name__)
        
        logger.info(
            "Starting securAIty API server",
            extra={
                "environment": os.getenv("APP_ENV", "development"),
                "debug": os.getenv("DEBUG", "false"),
                "api_prefix": os.getenv("API_PREFIX", "/api/v1"),
            },
        )
        
        logger.info("Database connection: pending")
        logger.info("NATS connection: pending")
        logger.info("Vault connection: pending")


def register_shutdown_events(app: FastAPI) -> None:
    @app.on_event("shutdown")
    async def shutdown_event() -> None:
        from securAIty.logging import get_logger
        
        logger = get_logger(__name__)
        
        logger.info("Shutting down securAIty API server")
        
        logger.info("Closing database connections")
        logger.info("Closing NATS connections")
        logger.info("Closing Vault connections")


def create_app() -> FastAPI:
    app = create_application()
    
    register_middleware(app)
    
    register_routers(app)
    
    create_exception_handler(app)
    
    register_startup_events(app)
    register_shutdown_events(app)
    
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "securAIty.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
