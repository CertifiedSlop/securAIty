import time
import logging
from datetime import datetime, timezone
from typing import Callable, Awaitable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from securAIty.logging import get_logger


logger = get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        include_body: bool = False,
        include_response_body: bool = False,
        log_level: str = "INFO",
        sensitive_headers: list[str] | None = None,
    ):
        super().__init__(app)
        self.include_body = include_body
        self.include_response_body = include_response_body
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.sensitive_headers = sensitive_headers or [
            "authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
        ]

    def sanitize_headers(self, headers: dict) -> dict:
        sanitized = {}
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in self.sensitive_headers:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value
        return sanitized

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = f"req_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        
        start_time = time.perf_counter()
        
        client_host = request.client.host if request.client else "unknown"
        client_port = request.client.port if request.client else "unknown"
        
        request_log_data = {
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query) if request.url.query else None,
            "client_ip": client_host,
            "client_port": client_port,
            "headers": self.sanitize_headers(dict(request.headers)),
            "path_params": dict(request.path_params) if request.path_params else None,
        }
        
        if self.include_body and request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                if body:
                    request_log_data["body"] = body.decode("utf-8", errors="replace")[:1000]
            except Exception as exc:
                request_log_data["body_error"] = str(exc)
        
        logger.log(
            self.log_level,
            "Incoming request",
            extra={"request_log": request_log_data},
        )
        
        try:
            response = await call_next(request)
            
            process_time = time.perf_counter() - start_time
            
            response_log_data = {
                "request_id": request_id,
                "status_code": response.status_code,
                "process_time_ms": round(process_time * 1000, 2),
                "headers": self.sanitize_headers(dict(response.headers)),
            }
            
            if self.include_response_body:
                try:
                    body_parts = []
                    async for chunk in response.body_iterator:
                        body_parts.append(chunk)
                    
                    body = b"".join(body_parts)
                    response_log_data["body"] = body.decode("utf-8", errors="replace")[:1000]
                    
                    response = Response(
                        content=body,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        media_type=response.media_type,
                    )
                except Exception as exc:
                    response_log_data["body_error"] = str(exc)
            
            log_level = self.log_level
            if response.status_code >= 500:
                log_level = logging.ERROR
            elif response.status_code >= 400:
                log_level = logging.WARNING
            
            logger.log(
                log_level,
                "Request completed",
                extra={"response_log": response_log_data},
            )
            
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = str(round(process_time * 1000, 2))
            
            return response
            
        except Exception as exc:
            process_time = time.perf_counter() - start_time
            
            error_log_data = {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "error": str(exc),
                "error_type": type(exc).__name__,
                "process_time_ms": round(process_time * 1000, 2),
            }
            
            logger.exception(
                "Request failed with exception",
                extra={"error_log": error_log_data},
            )
            
            raise


def setup_structured_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    if log_format == "json":
        import structlog
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, log_level.upper(), logging.INFO)
            ),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
