"""

Business logic for token operations:
creating, validating, rotating, and blacklisting tokens.
"""

import uuid

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
)
from app.core.exceptions import (
    RefreshTokenInvalidError,
    RefreshTokenReuseError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from app.db.redis import get_redis
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.token_repository import TokenRepository
from app.repositories.session_repository import SessionRepository
from app.config import settings

import jwt

log = structlog.get_logger()

# Redis key for blacklisted JWT IDs
BLACKLIST_KEY = "blacklist:{jti}"


class TokenService:
    """
    Handles all token lifecycle operations.
    Works with both JWT access tokens and opaque refresh tokens.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.token_repo = TokenRepository(db)
        self.session_repo = SessionRepository(db)

    async def create_tokens_for_user(
        self,
        user: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_info: str | None = None,
        family_id: uuid.UUID | None = None,
    ) -> dict:
        """
        Create a complete token pair (access + refresh) for a user.
        Also creates a session record.

        Called on:
        - Successful login (family_id=None → new family created)
        - Token rotation (family_id=existing → continues family chain)

        Returns a dict with all token data needed for the response.
        """
        # Create the raw refresh token string
        raw_refresh_token = create_refresh_token()

        # Store hashed refresh token in DB
        db_refresh_token = await self.token_repo.create(
            user_id=user.id,
            raw_token=raw_refresh_token,
            family_id=family_id,
        )

        # Create or update session
        if family_id is None:
            # New login → create new session
            session = await self.session_repo.create(
                user_id=user.id,
                refresh_token_id=db_refresh_token.id,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
            )
        else:
            # Token rotation → update existing session's refresh token link
            session = await self.session_repo.get_by_refresh_token_id(
                db_refresh_token.id
            )
            # If session not found (edge case), create a new one
            if not session:
                session = await self.session_repo.create(
                    user_id=user.id,
                    refresh_token_id=db_refresh_token.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    device_info=device_info,
                )

        # Create JWT access token
        access_token, jti = create_access_token(
            user_id=str(user.id),
            email=user.email,
            roles=user.role_names,
            session_id=str(session.id),
        )

        return {
            "access_token": access_token,
            "refresh_token": raw_refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.access_token_expire_minutes * 60,
            "jti": jti,
            "session_id": session.id,
        }

    async def verify_access_token(self, token: str) -> dict:
        """
        Verify a JWT access token and return its payload.

        Checks:
        1. JWT signature and expiry (PyJWT handles this)
        2. Token is not blacklisted in Redis
        3. Token type is 'access' (not some other token type)

        Raises appropriate exceptions on any failure.
        """
        # Step 1: Decode and verify JWT
        try:
            payload = decode_access_token(token)
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()
        except jwt.InvalidTokenError:
            raise TokenInvalidError()

        # Step 2: Check token type
        if payload.get("type") != "access":
            raise TokenInvalidError()

        # Step 3: Check Redis blacklist
        jti = payload.get("jti")
        if jti:
            redis = get_redis()
            is_blacklisted = await redis.exists(BLACKLIST_KEY.format(jti=jti))
            if is_blacklisted:
                raise TokenRevokedError()

        return payload

    async def rotate_refresh_token(
        self,
        raw_refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[RefreshToken, dict]:
        """
        Rotate a refresh token — invalidate old, issue new.

        This is the core of our security model:
        1. Find the token in DB
        2. Check if it's valid (not used, not revoked, not expired)
        3. If already USED → REUSE DETECTED → revoke entire family
        4. If valid → mark as used → issue new token pair

        Returns (old_token, new_token_data)
        """
        # Step 1: Find token
        token = await self.token_repo.get_by_raw_token(raw_refresh_token)

        if not token:
            raise RefreshTokenInvalidError()

        # Step 2: Check for reuse FIRST (before checking revoked/expired)
        # WHY? A used token might also be revoked (we revoke the family).
        # We want to give the reuse error, not the generic invalid error.
        if token.is_used:
            log.warning(
                "Refresh token reuse detected — revoking family",
                family_id=str(token.family_id),
                user_id=str(token.user_id),
            )
            # Revoke the entire family — attacker's current token dies too
            await self.token_repo.revoke_token_family(token.family_id)
            await self.db.commit()
            raise RefreshTokenReuseError()

        # Step 3: Check revoked and expiry
        if not await self.token_repo.is_token_valid(token):
            raise RefreshTokenInvalidError()

        return token

    async def blacklist_access_token(
        self,
        jti: str,
        expires_in_seconds: int,
    ) -> None:
        """
        Add a JWT's ID to the Redis blacklist.

        WHY TTL = remaining token lifetime?
        After the token would have expired naturally, we don't need
        to keep it blacklisted anymore (expired tokens are already
        rejected by PyJWT). This keeps Redis memory usage minimal.
        """
        if expires_in_seconds > 0:
            redis = get_redis()
            await redis.setex(
                BLACKLIST_KEY.format(jti=jti),
                expires_in_seconds,
                "1",
            )

    async def revoke_all_user_tokens(self, user_id: uuid.UUID) -> None:
        """Revoke all tokens and deactivate all sessions for a user."""
        await self.token_repo.revoke_all_user_tokens(user_id)
        await self.session_repo.deactivate_all_for_user(user_id)