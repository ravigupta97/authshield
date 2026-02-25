"""

Pydantic schemas for OAuth endpoints.
"""

import uuid
from pydantic import BaseModel


class OAuthUserResponse(BaseModel):
    """User data returned after OAuth login."""
    id: uuid.UUID
    email: str
    full_name: str
    roles: list[str]
    is_2fa_enabled: bool
    is_new_user: bool       # True if this OAuth login created a new account


class OAuthLoginResponse(BaseModel):
    """Complete response after successful OAuth authentication."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: OAuthUserResponse