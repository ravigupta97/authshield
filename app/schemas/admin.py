"""

Pydantic schemas for admin endpoints.

Admin responses include more fields than regular user responses
because admins need the full picture — including sensitive
status fields that regular users don't need to see.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel


class AdminUserResponse(BaseModel):
    """
    Full user details as seen by an admin.
    Includes fields not shown in regular UserResponse.
    Still excludes: password_hash, totp_secret (never exposed via API).
    """
    id: uuid.UUID
    email: str
    full_name: str
    avatar_url: str | None
    is_active: bool
    is_verified: bool
    is_2fa_enabled: bool
    oauth_provider: str | None
    roles: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_user(cls, user) -> "AdminUserResponse":
        return cls(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            is_verified=user.is_verified,
            is_2fa_enabled=user.is_2fa_enabled,
            oauth_provider=user.oauth_provider,
            roles=user.role_names,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


class AdminUserListResponse(BaseModel):
    """Paginated list of users for admin."""
    users: list[AdminUserResponse]
    total: int
    page: int
    limit: int
    total_pages: int


class RoleUpdateRequest(BaseModel):
    """
    Replace a user's entire role set.

    WHY replace instead of add/remove individually?
    Simpler API — client sends the complete desired role list.
    No need for separate add-role and remove-role endpoints.
    Easier to reason about: what you send is exactly what the user gets.
    """
    roles: list[str]

    def validate_roles(self) -> list[str]:
        """Ensure only valid role names are accepted."""
        valid_roles = {"user", "admin", "moderator"}
        invalid = set(self.roles) - valid_roles
        if invalid:
            raise ValueError(
                f"Invalid roles: {invalid}. "
                f"Valid roles are: {valid_roles}"
            )
        if not self.roles:
            raise ValueError("User must have at least one role.")
        return self.roles


class StatusUpdateRequest(BaseModel):
    """Activate or deactivate a user account."""
    is_active: bool


class AdminSessionResponse(BaseModel):
    """Session details as seen by an admin."""
    id: uuid.UUID
    user_id: uuid.UUID
    ip_address: str | None
    user_agent: str | None
    device_info: str | None
    is_active: bool
    last_active_at: datetime | None
    created_at: datetime
    expires_at: datetime

    model_config = {"from_attributes": True}