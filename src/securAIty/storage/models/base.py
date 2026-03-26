"""
Base Model

Base classes and common utilities for all SQLAlchemy models.
"""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy models.

    Provides common functionality and configuration
    for all database entities.
    """

    def to_dict(self) -> dict[str, Any]:
        """
        Convert model to dictionary.

        Returns:
            Dictionary representation of the model
        """
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }

    def __repr__(self) -> str:
        """
        String representation of the model.

        Returns:
            String representation
        """
        pk_value = getattr(self, self.__table__.primary_key.columns.keys()[0])
        return f"<{self.__class__.__name__} {pk_value}>"


class TimestampMixin:
    """
    Mixin for adding timestamp columns to models.

    Adds created_at and updated_at columns for audit purposes.

    Attributes:
        created_at: When the record was created
        updated_at: When the record was last updated
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
