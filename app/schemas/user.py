"""

Pydantic schemas for user profile endpoints.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserResponse(BaseModel):
    """
    Full user profile returned from GET /users/me.

    Notice what's NOT here: password_hash, totp_secret.
    We NEVER return sensitive fields in API responses.
    """
    id: uuid.UUID
    email: str
    full_name: str
    avatar_url: str | None
    is_verified: bool
    is_2fa_enabled: bool
    oauth_provider: str | None
    roles: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_user(cls, user) -> "UserResponse":
        """Build response from a User ORM model instance."""
        return cls(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            avatar_url=user.avatar_url,
            is_verified=user.is_verified,
            is_2fa_enabled=user.is_2fa_enabled,
            oauth_provider=user.oauth_provider,
            roles=user.role_names,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


class UpdateProfileRequest(BaseModel):
    """Fields the user can update on their own profile."""
    full_name: str | None = None
    avatar_url: str | None = None

    model_config = {"str_strip_whitespace": True}