"""

Shared Pydantic schemas used across multiple endpoints.

The StandardResponse wrapper ensures EVERY response from AuthShield
has the same shape. Consuming applications always know what to expect.
"""

from typing import Any, Generic, TypeVar

from pydantic import BaseModel

# T is a type variable — allows StandardResponse to be typed with
# any data payload. e.g., StandardResponse[UserResponse]
T = TypeVar("T")


class StandardResponse(BaseModel, Generic[T]):
    """
    Every API response wraps its data in this structure.

    Success example:
    {
        "status": "success",
        "message": "Login successful",
        "data": { "access_token": "...", ... }
    }

    Error example:
    {
        "status": "error",
        "message": "Invalid credentials",
        "data": null
    }

    Universal API response wrapper.

    All endpoints return this shape:
    {
        "status": "success" | "error",
        "message": "Human readable description",
        "data": { ... } | null
    }

    WHY a wrapper?
    Consistency. API consumers always know where to find data,
    errors, and status. No guessing whether this endpoint returns
    { "user": {...} } or { "data": {...} } or just { ... }.
    
    """
    status: str
    message: str
    data: T | None = None

    @classmethod
    def success(
        cls,
        message: str = "Success.",
        data=None,
    ) -> "StandardResponse":
        return cls(status="success", message=message, data=data)

    @classmethod
    def error(
        cls,
        message: str,
        data=None,
    ) -> "StandardResponse":
        return cls(status="error", message=message, data=data)


class ErrorDetail(BaseModel):
    """Structure for validation error details."""
    field: str
    message: str
    type: str


class ErrorResponse(BaseModel):
    """
    Error response shape returned when exceptions occur.

    {
        "status": "error",
        "message": "Human readable message",
        "error_code": "AUTH_INVALID_CREDENTIALS",
        "details": null
    }
    """
    status: str = "error"
    message: str
    error_code: str
    details: dict | str | None = None


class PaginatedData(BaseModel, Generic[T]):
    """Wrapper for paginated list responses."""
    items: list[T]
    total: int
    page: int
    limit: int
    total_pages: int