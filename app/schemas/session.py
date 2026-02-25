"""

Pydantic schemas for session management endpoints.
Used by both regular users (view own sessions) and admins.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel


class SessionResponse(BaseModel):
    """
    Session data returned to the user.
    Shows enough to identify the device without exposing internals.
    """
    id: uuid.UUID
    ip_address: str | None
    user_agent: str | None
    device_info: str | None
    is_current: bool           # True if this is the session making the request
    is_active: bool
    last_active_at: datetime | None
    created_at: datetime
    expires_at: datetime

    model_config = {"from_attributes": True}


class SessionListResponse(BaseModel):
    """List of sessions with total count."""
    sessions: list[SessionResponse]
    total: int