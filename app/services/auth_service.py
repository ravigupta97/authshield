"""

Business logic for authentication operations.

This layer:
- Enforces business rules ("email must be unique", "must be verified to login")
- Orchestrates multiple repositories and utilities
- Knows NOTHING about HTTP (no Request/Response objects)
- Knows NOTHING about raw SQL (uses repositories)
"""

import uuid

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import (
    AccountDisabledError,
    EmailAlreadyRegisteredError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidVerificationTokenError,
    RefreshTokenInvalidError,
)
from app.core.security import (
    decode_access_token,
    generate_secure_token,
    hash_password,
    verify_password,
)
from app.db.redis import get_redis
from app.repositories.login_history_repository import LoginHistoryRepository
from app.repositories.token_repository import TokenRepository
from app.repositories.user_repository import UserRepository
from app.services.email_service import email_service
from app.services.token_service import TokenService

import jwt

log = structlog.get_logger()

VERIFY_TOKEN_KEY = "email_verify:{token}"
VERIFY_TOKEN_TTL = 86400  # 24 hours


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.history_repo = LoginHistoryRepository(db)
        self.token_service = TokenService(db)
        self.token_repo = TokenRepository(db)

    async def register(
        self,
        email: str,
        password: str,
        full_name: str,
    ) -> dict:
        """Register a new user. (unchanged)"""
        if await self.user_repo.email_exists(email):
            raise EmailAlreadyRegisteredError()

        password_hash = hash_password(password)

        user = await self.user_repo.create(
            email=email,
            full_name=full_name,
            password_hash=password_hash,
            is_verified=False,
        )

        await self.user_repo.assign_role(user, "user")

        token = generate_secure_token(64)
        redis = get_redis()
        await redis.setex(
            VERIFY_TOKEN_KEY.format(token=token),
            VERIFY_TOKEN_TTL,
            str(user.id),
        )

        await self.db.commit()
        await self.db.refresh(user)

        await email_service.send_verification_email(
            to_email=user.email,
            full_name=user.full_name,
            token=token,
        )

        log.info("User registered", user_id=str(user.id), email=user.email)

        return {
            "user_id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_verified": user.is_verified,
            "created_at": user.created_at,
        }

    async def login(
        self,
        email: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        """Authenticate user and issue tokens. (unchanged)"""
        user = await self.user_repo.get_by_email(email)

        dummy_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK8."
        password_to_check = user.password_hash if user else dummy_hash
        password_valid = verify_password(password, password_to_check)

        if not user or not password_valid:
            await self.history_repo.record(
                status="failed",
                user_id=user.id if user else None,
                ip_address=ip_address,
                user_agent=user_agent,
                failure_reason="wrong_password" if user else "email_not_found",
            )
            await self.db.commit()
            raise InvalidCredentialsError()

        if not user.is_verified:
            await self.history_repo.record(
                status="failed",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                failure_reason="unverified_email",
            )
            await self.db.commit()
            raise EmailNotVerifiedError()

        if not user.is_active:
            await self.history_repo.record(
                status="failed",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                failure_reason="account_disabled",
            )
            await self.db.commit()
            raise AccountDisabledError()

        if user.is_2fa_enabled:
            temp_token = generate_secure_token(32)
            redis = get_redis()
            await redis.setex(f"2fa_temp:{temp_token}", 300, str(user.id))
            from app.core.exceptions import TwoFactorRequiredError
            raise TwoFactorRequiredError(temp_token=temp_token)

        device_info = self._parse_device_info(user_agent)

        token_data = await self.token_service.create_tokens_for_user(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
        )

        await self.history_repo.record(
            status="success",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        await self.db.commit()

        log.info(
            "User logged in",
            user_id=str(user.id),
            email=user.email,
            ip=ip_address,
        )

        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "token_type": token_data["token_type"],
            "expires_in": token_data["expires_in"],
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "roles": user.role_names,
                "is_2fa_enabled": user.is_2fa_enabled,
            },
        }

    async def refresh_tokens(
        self,
        raw_refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        """
        Rotate a refresh token and issue a new token pair.

        The client should call this when the access token expires.
        The old refresh token is immediately invalidated.
        The new refresh token must be stored and used next time.

        CRITICAL: The client must replace BOTH tokens from this response.
        Keeping the old refresh token and trying to use it again will
        trigger reuse detection and revoke all sessions.
        """
        # First find the token to get user_id, then load user
        token = await self.token_repo.get_by_raw_token(raw_refresh_token)

        if not token:
            raise RefreshTokenInvalidError()

        # Load the user (we need their current roles for the new JWT)
        user = await self.user_repo.get_by_id(token.user_id)
        if not user or not user.is_active:
            raise RefreshTokenInvalidError()

        # Perform the rotation (handles reuse detection internally)
        new_token_data = await self.token_service.rotate_refresh_token(
            raw_refresh_token=raw_refresh_token,
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        await self.db.commit()

        return {
            "access_token": new_token_data["access_token"],
            "refresh_token": new_token_data["refresh_token"],
            "token_type": new_token_data["token_type"],
            "expires_in": new_token_data["expires_in"],
        }

    async def logout(
        self,
        access_token: str,
        refresh_token: str | None = None,
    ) -> None:
        """
        Logout a user by invalidating their current tokens.

        TWO things happen:
        1. Access token JTI → Redis blacklist (immediate invalidation)
        2. Refresh token → marked revoked in DB (can't refresh again)

        WHY blacklist the access token?
        JWTs are stateless — without blacklisting, a logged-out user's
        access token stays valid until it naturally expires (up to 15 min).
        The blacklist makes logout truly immediate.

        WHY use JTI instead of the full token as the key?
        The JTI is a short random string (~43 chars).
        The full JWT is much longer (~200+ chars).
        Less memory in Redis for the same result.
        """
        # Step 1: Decode the access token to get JTI and expiry
        # We don't use verify_access_token() here because that would
        # raise TokenRevokedError if the token is already blacklisted.
        # We want logout to be idempotent (calling it twice is fine).
        try:
            payload = decode_access_token(access_token)
            jti = payload.get("jti")

            if jti:
                remaining_seconds = (
                    self.token_service.get_token_remaining_seconds(payload)
                )
                await self.token_service.blacklist_access_token(
                    jti=jti,
                    expires_in_seconds=remaining_seconds,
                )
        except jwt.InvalidTokenError:
            # Token is already invalid/expired — that's fine for logout
            pass

        # Step 2: Revoke the refresh token in the database
        if refresh_token:
            db_token = await self.token_repo.get_by_raw_token(refresh_token)
            if db_token and not db_token.is_revoked:
                await self.token_repo.revoke_token(db_token)

                # Deactivate the associated session
                from app.repositories.session_repository import SessionRepository
                session_repo = SessionRepository(self.db)
                session = await session_repo.get_by_refresh_token_id(
                    db_token.id
                )
                if session:
                    await session_repo.deactivate(session)

        await self.db.commit()
        log.info("User logged out")

    async def logout_all(self, user_id: uuid.UUID, access_token: str) -> None:
        """
        Logout from ALL devices simultaneously.

        Blacklists the current access token AND revokes every
        refresh token this user has ever been issued.
        All active sessions are deactivated.
        """
        # Blacklist the current access token
        try:
            payload = decode_access_token(access_token)
            jti = payload.get("jti")
            if jti:
                remaining = self.token_service.get_token_remaining_seconds(
                    payload
                )
                await self.token_service.blacklist_access_token(
                    jti=jti,
                    expires_in_seconds=remaining,
                )
        except jwt.InvalidTokenError:
            pass

        # Revoke ALL refresh tokens and deactivate ALL sessions
        await self.token_service.revoke_all_user_tokens(user_id)
        await self.db.commit()

        log.info("User logged out from all devices", user_id=str(user_id))

    def _parse_device_info(self, user_agent: str | None) -> str | None:
        """Parse human-readable device info from User-Agent string."""
        if not user_agent:
            return None

        ua = user_agent.lower()

        if "windows" in ua:
            os = "Windows"
        elif "macintosh" in ua or "mac os" in ua:
            os = "macOS"
        elif "iphone" in ua:
            os = "iPhone"
        elif "ipad" in ua:
            os = "iPad"
        elif "android" in ua:
            os = "Android"
        elif "linux" in ua:
            os = "Linux"
        else:
            os = "Unknown OS"

        if "edg/" in ua:
            browser = "Edge"
        elif "chrome" in ua and "chromium" not in ua:
            browser = "Chrome"
        elif "firefox" in ua:
            browser = "Firefox"
        elif "safari" in ua and "chrome" not in ua:
            browser = "Safari"
        elif "postman" in ua:
            browser = "Postman"
        else:
            browser = "Unknown Browser"

        return f"{browser} on {os}"

    async def verify_email(self, token: str) -> None:
        """Verify a user's email address. (unchanged)"""
        redis = get_redis()
        key = VERIFY_TOKEN_KEY.format(token=token)
        user_id = await redis.get(key)

        if not user_id:
            raise InvalidVerificationTokenError()

        user = await self.user_repo.get_by_id(uuid.UUID(user_id))
        if not user:
            raise InvalidVerificationTokenError()

        await self.user_repo.update(user, is_verified=True)
        await redis.delete(key)
        await self.db.commit()

        log.info("Email verified", user_id=str(user.id), email=user.email)

    async def resend_verification(self, email: str) -> None:
        """Resend verification email. (unchanged)"""
        user = await self.user_repo.get_by_email(email)
        if not user or user.is_verified:
            return

        token = generate_secure_token(64)
        redis = get_redis()
        await redis.setex(
            VERIFY_TOKEN_KEY.format(token=token),
            VERIFY_TOKEN_TTL,
            str(user.id),
        )

        await email_service.send_verification_email(
            to_email=user.email,
            full_name=user.full_name,
            token=token,
        )

        log.info("Verification email resent", email=email)