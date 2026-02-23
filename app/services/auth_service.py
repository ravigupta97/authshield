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

from app.core.security import (
    generate_secure_token,
    hash_password,
    verify_password,
)
from app.core.exceptions import (
    AccountDisabledError,
    EmailAlreadyRegisteredError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidVerificationTokenError,
)
from app.db.redis import get_redis
from app.repositories.user_repository import UserRepository
from app.repositories.login_history_repository import LoginHistoryRepository
from app.services.email_service import email_service
from app.services.token_service import TokenService
from app.config import settings

log = structlog.get_logger()

VERIFY_TOKEN_KEY = "email_verify:{token}"
VERIFY_TOKEN_TTL = 86400  # 24 hours


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.history_repo = LoginHistoryRepository(db)
        self.token_service = TokenService(db)

    async def register(
        self,
        email: str,
        password: str,
        full_name: str,
    ) -> dict:
        """Register a new user. (unchanged from Step 3)"""

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
        """
        Authenticate a user and issue tokens.

        SECURITY NOTES:
        - We always say "invalid email or password" — never reveal
          which field is wrong (prevents user enumeration).
        - We log the failure reason internally for monitoring.
        - We record every attempt (success and failure) in login_history.
        - Password check happens AFTER user lookup. If user doesn't
          exist, we still call verify_password() with a dummy hash.
          WHY? To prevent timing attacks — an attacker measuring
          response time could tell if an email exists based on whether
          we skipped the bcrypt check (which takes ~250ms).
        """
        user = await self.user_repo.get_by_email(email)

        # Timing-safe: always run bcrypt even if user not found
        dummy_hash = "$2b$12$dummy.hash.to.prevent.timing.attacks.xxxxx"
        password_to_check = user.password_hash if user else dummy_hash
        password_valid = verify_password(password, password_to_check)

        # Now check all conditions (but give same error message externally)
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

        # Check if 2FA is required (we'll fully implement this in Step 13)
        if user.is_2fa_enabled:
            temp_token = generate_secure_token(32)
            redis = get_redis()
            await redis.setex(f"2fa_temp:{temp_token}", 300, str(user.id))
            from app.core.exceptions import TwoFactorRequiredError
            raise TwoFactorRequiredError(temp_token=temp_token)

        # Parse device info from user agent string
        device_info = self._parse_device_info(user_agent)

        # Create tokens and session
        token_data = await self.token_service.create_tokens_for_user(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
        )

        # Record successful login
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

    def _parse_device_info(self, user_agent: str | None) -> str | None:
        """
        Parse a human-readable device description from User-Agent string.
        Simple heuristic — good enough for session display purposes.
        """
        if not user_agent:
            return None

        ua = user_agent.lower()

        # Detect OS
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

        # Detect browser
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
        """Verify a user's email address. (unchanged from Step 3)"""
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
        """Resend verification email. (unchanged from Step 3)"""
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