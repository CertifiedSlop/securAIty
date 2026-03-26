from datetime import datetime
from typing import Generic, TypeVar, Optional, List
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


DataT = TypeVar("DataT")


class PaginatedRequest(BaseModel):
    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page (max 100)")


class PaginatedResponse(BaseModel, Generic[DataT]):
    items: List[DataT] = Field(description="List of items on current page")
    total: int = Field(description="Total number of items across all pages")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Number of items per page")
    total_pages: int = Field(description="Total number of pages")

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def create(
        cls,
        items: List[DataT],
        total: int,
        page: int,
        page_size: int,
    ) -> "PaginatedResponse[DataT]":
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0
        return cls(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )


class ApiResponse(BaseModel, Generic[DataT]):
    success: bool = Field(default=True, description="Indicates if the request was successful")
    data: Optional[DataT] = Field(default=None, description="Response data payload")
    message: Optional[str] = Field(default=None, description="Optional message or error description")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")

    model_config = ConfigDict(from_attributes=True)


class ErrorResponse(BaseModel):
    error_code: str = Field(description="Machine-readable error code")
    message: str = Field(description="Human-readable error message")
    details: Optional[dict] = Field(default=None, description="Additional error details")
    path: str = Field(description="Request path that caused the error")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")

    model_config = ConfigDict(from_attributes=True)
