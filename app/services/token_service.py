"""

Business logic for all token lifecycle operations.
Creating, verifying, rotating, and blacklisting tokens.
"""

import uuid
from datetime import datetime, timezone

import jwt
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import (
    RefreshTokenInvalidError,
    RefreshTokenReuseError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
)
from app.db.redis import get_redis
from app.models.user import User
from app.repositories.session_repository import SessionRepository
from app.repositories.token_repository import TokenRepository

log = structlog.get_logger()

# Redis key templates
BLACKLIST_KEY = "blacklist:{jti}"


class TokenService:
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

        family_id=None  → brand new login, new family created
        family_id=value → rotation, continues existing family chain
        """
        raw_refresh_token = create_refresh_token()

        # Store hashed refresh token in DB
        db_refresh_token = await self.token_repo.create(
            user_id=user.id,
            raw_token=raw_refresh_token,
            family_id=family_id,
        )

        # New login → create new session
        if family_id is None:
            session = await self.session_repo.create(
                user_id=user.id,
                refresh_token_id=db_refresh_token.id,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
            )
        else:
            # Token rotation → find existing session and link new token
            # We need to find the session by user_id and update it
            sessions = await self.session_repo.get_active_sessions_for_user(
                user.id
            )
            # Find the session that matches our family (most recently active)
            session = sessions[0] if sessions else None

            if not session:
                # Edge case: session was manually revoked, create new one
                session = await self.session_repo.create(
                    user_id=user.id,
                    refresh_token_id=db_refresh_token.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    device_info=device_info,
                )
            else:
                # Update session to point to the new refresh token
                session.refresh_token_id = db_refresh_token.id
                await self.session_repo.update_last_active(session)

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

        Checks in order:
        1. JWT signature and expiry (PyJWT)
        2. Token type is 'access'
        3. Not blacklisted in Redis
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
        user,                        # User object (loaded by caller)
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        """
        Rotate a refresh token — invalidate old, issue new pair.

        This is the core of our refresh token security model.

        REUSE DETECTION LOGIC:
        If someone presents a token that was already used (is_used=True),
        it means either:
        a) The legitimate user's token was stolen, attacker used it first
        b) The attacker's stolen token was used, legitimate user tried theirs

        Either way: revoke the ENTIRE family. Both parties are kicked out.
        The legitimate user must re-login. Minor inconvenience vs security.
        """
        # Step 1: Find token in DB
        token = await self.token_repo.get_by_raw_token(raw_refresh_token)

        if not token:
            raise RefreshTokenInvalidError()

        # Step 2: Reuse detection FIRST
        # Check is_used before is_revoked — a reused token might also
        # be revoked (we revoke the family on detection). We want to
        # give the specific reuse error, not the generic invalid error.
        if token.is_used:
            log.warning(
                "Refresh token reuse detected — revoking entire family",
                family_id=str(token.family_id),
                user_id=str(token.user_id),
            )
            await self.token_repo.revoke_token_family(token.family_id)
            await self.db.commit()
            raise RefreshTokenReuseError()

        # Step 3: Check revoked and expiry
        if not await self.token_repo.is_token_valid(token):
            raise RefreshTokenInvalidError()

        # Step 4: Verify token belongs to the correct user
        # (Extra safety: prevent using another user's refresh token)
        if token.user_id != user.id:
            raise RefreshTokenInvalidError()

        # Step 5: Mark old token as used and record what replaced it
        # We'll update replaced_by_id after creating the new token
        token.is_used = True
        await self.db.flush()

        # Step 6: Create new token pair (same family_id = continues chain)
        new_token_data = await self.create_tokens_for_user(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            family_id=token.family_id,  # ← Same family, continues chain
        )

        # Step 7: Link old token to new one (for audit chain)
        new_db_token = await self.token_repo.get_by_raw_token(
            new_token_data["refresh_token"]
        )
        if new_db_token:
            token.replaced_by_id = new_db_token.id

        log.info(
            "Refresh token rotated",
            user_id=str(user.id),
            family_id=str(token.family_id),
        )

        return new_token_data

    async def blacklist_access_token(
        self,
        jti: str,
        expires_in_seconds: int,
    ) -> None:
        """
        Add a JWT's unique ID to Redis blacklist.

        TTL = remaining token lifetime.
        Once the token would have naturally expired, Redis
        automatically removes the blacklist entry. Self-cleaning.
        """
        if expires_in_seconds > 0:
            redis = get_redis()
            await redis.setex(
                BLACKLIST_KEY.format(jti=jti),
                expires_in_seconds,
                "1",
            )
            log.info("Access token blacklisted", jti=jti)

    def get_token_remaining_seconds(self, payload: dict) -> int:
        """
        Calculate how many seconds remain until a JWT expires.
        Used to set the Redis blacklist TTL precisely.
        """
        exp = payload.get("exp", 0)
        now = datetime.now(timezone.utc).timestamp()
        remaining = int(exp - now)
        return max(remaining, 0)  # Never negative

    async def revoke_all_user_tokens(self, user_id: uuid.UUID) -> None:
        """
        Revoke all tokens and deactivate all sessions for a user.
        Used on: logout-all, password reset, account deactivation.
        """
        await self.token_repo.revoke_all_user_tokens(user_id)
        await self.session_repo.deactivate_all_for_user(user_id)
        log.info("All tokens revoked for user", user_id=str(user_id))