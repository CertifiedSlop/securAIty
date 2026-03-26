import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Awaitable, Dict, Tuple

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitConfig:
    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        burst_limit: int = 10,
        burst_window_seconds: int = 1,
        enabled: bool = True,
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.burst_limit = burst_limit
        self.burst_window_seconds = burst_window_seconds
        self.enabled = enabled

    @classmethod
    def default(cls) -> "RateLimitConfig":
        return cls(
            requests_per_minute=60,
            requests_per_hour=1000,
            burst_limit=10,
            burst_window_seconds=1,
            enabled=True,
        )

    @classmethod
    def strict(cls) -> "RateLimitConfig":
        return cls(
            requests_per_minute=30,
            requests_per_hour=500,
            burst_limit=5,
            burst_window_seconds=1,
            enabled=True,
        )

    @classmethod
    def relaxed(cls) -> "RateLimitConfig":
        return cls(
            requests_per_minute=120,
            requests_per_hour=2000,
            burst_limit=20,
            burst_window_seconds=1,
            enabled=True,
        )

    @classmethod
    def from_env(cls) -> "RateLimitConfig":
        import os
        
        enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
        requests_per_minute = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
        requests_per_hour = int(os.getenv("RATE_LIMIT_PER_HOUR", "1000"))
        burst_limit = int(os.getenv("RATE_LIMIT_BURST", "10"))
        burst_window = int(os.getenv("RATE_LIMIT_BURST_WINDOW", "1"))
        
        return cls(
            requests_per_minute=requests_per_minute,
            requests_per_hour=requests_per_hour,
            burst_limit=burst_limit,
            burst_window_seconds=burst_window,
            enabled=enabled,
        )


class SlidingWindowRateLimiter:
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.requests_minute: Dict[str, list[float]] = defaultdict(list)
        self.requests_hour: Dict[str, list[float]] = defaultdict(list)
        self.burst_requests: Dict[str, list[float]] = defaultdict(list)

    def _cleanup_old_entries(self, storage: Dict[str, list[float]], window_seconds: int) -> None:
        cutoff = time.time() - window_seconds
        for key in list(storage.keys()):
            storage[key] = [ts for ts in storage[key] if ts > cutoff]
            if not storage[key]:
                del storage[key]

    def _get_client_identifier(self, request: Request) -> str:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        if request.client:
            return request.client.host
        
        return "unknown"

    def check_rate_limit(self, request: Request) -> Tuple[bool, Dict[str, int]]:
        client_id = self._get_client_identifier(request)
        now = time.time()
        
        self._cleanup_old_entries(self.requests_minute, 60)
        self._cleanup_old_entries(self.requests_hour, 3600)
        self._cleanup_old_entries(self.burst_requests, self.config.burst_window_seconds)
        
        minute_count = len(self.requests_minute.get(client_id, []))
        hour_count = len(self.requests_hour.get(client_id, []))
        burst_count = len(self.burst_requests.get(client_id, []))
        
        headers = {
            "X-RateLimit-Limit-Minute": self.config.requests_per_minute,
            "X-RateLimit-Remaining-Minute": max(0, self.config.requests_per_minute - minute_count - 1),
            "X-RateLimit-Limit-Hour": self.config.requests_per_hour,
            "X-RateLimit-Remaining-Hour": max(0, self.config.requests_per_hour - hour_count - 1),
            "X-RateLimit-Reset": int(now + 60),
        }
        
        if burst_count >= self.config.burst_limit:
            headers["Retry-After"] = str(self.config.burst_window_seconds)
            return False, headers
        
        if minute_count >= self.config.requests_per_minute:
            headers["Retry-After"] = "60"
            return False, headers
        
        if hour_count >= self.config.requests_per_hour:
            headers["Retry-After"] = "3600"
            return False, headers
        
        self.requests_minute[client_id].append(now)
        self.requests_hour[client_id].append(now)
        self.burst_requests[client_id].append(now)
        
        headers["X-RateLimit-Remaining-Minute"] = max(0, self.config.requests_per_minute - minute_count - 1)
        headers["X-RateLimit-Remaining-Hour"] = max(0, self.config.requests_per_hour - hour_count - 1)
        
        return True, headers


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        config: RateLimitConfig | None = None,
        excluded_paths: list[str] | None = None,
    ):
        super().__init__(app)
        self.config = config or RateLimitConfig.from_env()
        self.rate_limiter = SlidingWindowRateLimiter(self.config)
        self.excluded_paths = excluded_paths or [
            "/health",
            "/ready",
            "/docs",
            "/openapi.json",
            "/redoc",
        ]

    def _is_excluded_path(self, path: str) -> bool:
        for excluded in self.excluded_paths:
            if path.startswith(excluded):
                return True
        return False

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not self.config.enabled:
            return await call_next(request)
        
        if self._is_excluded_path(request.url.path):
            return await call_next(request)
        
        is_allowed, headers = self.rate_limiter.check_rate_limit(request)
        
        if not is_allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later.",
                headers=headers,
            )
        
        response = await call_next(request)
        
        for header, value in headers.items():
            response.headers[header] = str(value)
        
        return response
