from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


class CORSConfig:
    def __init__(
        self,
        allow_origins: List[str] | None = None,
        allow_credentials: bool = False,
        allow_methods: List[str] | None = None,
        allow_headers: List[str] | None = None,
        allow_origin_regex: Optional[str] = None,
        expose_headers: List[str] | None = None,
        max_age: int = 600,
    ):
        self.allow_origins = allow_origins or ["*"]
        self.allow_credentials = allow_credentials
        self.allow_methods = allow_methods or ["*"]
        self.allow_headers = allow_headers or ["*"]
        self.allow_origin_regex = allow_origin_regex
        self.expose_headers = expose_headers or ["X-Request-ID", "X-Process-Time"]
        self.max_age = max_age

    @classmethod
    def development(cls) -> "CORSConfig":
        return cls(
            allow_origins=["*"],
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["X-Request-ID", "X-Process-Time"],
            max_age=600,
        )

    @classmethod
    def production(
        cls,
        allowed_origins: List[str],
        allow_credentials: bool = True,
    ) -> "CORSConfig":
        return cls(
            allow_origins=allowed_origins,
            allow_credentials=allow_credentials,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "X-Request-ID",
                "Accept",
                "Origin",
            ],
            expose_headers=["X-Request-ID", "X-Process-Time"],
            max_age=3600,
        )

    @classmethod
    def from_env(cls) -> "CORSConfig":
        import os
        
        env = os.getenv("APP_ENV", "development")
        
        if env == "production":
            allowed_origins_str = os.getenv("CORS_ALLOWED_ORIGINS", "")
            allowed_origins = [
                origin.strip()
                for origin in allowed_origins_str.split(",")
                if origin.strip()
            ]
            
            if not allowed_origins:
                allowed_origins = ["https://app.securAIty.com"]
            
            allow_credentials = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() == "true"
            
            return cls.production(
                allowed_origins=allowed_origins,
                allow_credentials=allow_credentials,
            )
        
        return cls.development()


def setup_cors_middleware(app: FastAPI, config: Optional[CORSConfig] = None) -> None:
    if config is None:
        config = CORSConfig.from_env()
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.allow_origins,
        allow_credentials=config.allow_credentials,
        allow_methods=config.allow_methods,
        allow_headers=config.allow_headers,
        allow_origin_regex=config.allow_origin_regex,
        expose_headers=config.expose_headers,
        max_age=config.max_age,
    )
