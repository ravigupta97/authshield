"""

Pydantic schemas for authentication endpoints.

MODELS vs SCHEMAS:
- Models (app/models/) = SQLAlchemy = how data is STORED in the DB
- Schemas (app/schemas/) = Pydantic = how data is RECEIVED and SENT via API

They are intentionally separate. Your DB might store 20 fields,
but your API only receives 3 and returns 8. Never return password_hash.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, field_validator

from app.core.security import validate_password_strength


# ── Registration ──────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    """
    What the client sends to POST /auth/register.
    Pydantic validates types and runs our custom validators.
    """
    email: EmailStr          # Pydantic validates email format automatically
    password: str
    full_name: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """
        Run our password strength rules.
        Pydantic calls this automatically during model instantiation.
        If we return errors, Pydantic raises a ValidationError
        which FastAPI converts to a 422 response automatically.
        """
        errors = validate_password_strength(v)
        if errors:
            # Join all errors into one message
            raise ValueError(" | ".join(errors))
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Full name must be at least 2 characters.")
        if len(v) > 100:
            raise ValueError("Full name must not exceed 100 characters.")
        return v


class RegisterResponse(BaseModel):
    """What we return after successful registration."""
    user_id: uuid.UUID
    email: str
    full_name: str
    is_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}  # Allow creating from ORM model


# ── Email Verification ────────────────────────────────────────────

class VerifyEmailRequest(BaseModel):
    """Token from the verification email link."""
    token: str


class ResendVerificationRequest(BaseModel):
    """Request to resend the verification email."""
    email: EmailStr


# ── Login ─────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserInToken(BaseModel):
    """User data embedded in the login response."""
    id: uuid.UUID
    email: str
    full_name: str
    roles: list[str]
    is_2fa_enabled: bool

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """
    Returned after successful login or token refresh.
    Both access and refresh tokens together.
    """
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int  # Seconds until access token expires


class LoginResponse(BaseModel):
    """Full login response including token data and user info."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: UserInToken


# ── Token Refresh ─────────────────────────────────────────────────

class RefreshRequest(BaseModel):
    refresh_token: str


# ── Logout ────────────────────────────────────────────────────────

class LogoutRequest(BaseModel):
    refresh_token: str | None = None  # Optional but recommended