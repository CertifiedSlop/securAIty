"""
Database Migrations

Alembic migration configuration and utilities for securAIty.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection

from securAIty.storage.models.base import Base
from securAIty.storage.models import (
    SecurityEvent,
    Incident,
    IncidentNote,
    Agent,
    AgentTask,
    AuditLog,
)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    """
    Get database URL from configuration or environment.

    Returns:
        Database URL string
    """
    import os
    
    url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://user:password@localhost:5432/security_db",
    )
    
    if not url.startswith("postgresql+asyncpg"):
        url = url.replace("postgresql://", "postgresql+asyncpg://")
    
    return url


def run_migrations_offline() -> None:
    """
    Run migrations in offline mode.

    No database connection required.
    """
    url = get_url()
    
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in online mode.

    Requires active database connection.
    """
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()
    
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
